rule sedexp: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects sedexp samples - 202408"
                                						
        strings:
                $sedexp_00 = "sedexp"
                $sedexp_01 = "HOME=/proc"
                $sedexp_02 = "kdevtmpfs"
                $sedexp_03 = "/lib/udev/%s"
                $sedexp_04 = "/proc/self/exe"
                $sedexp_05 = "pkill"
                $sedexp_06 = "/lib/modules/%s"

        condition:
                                uint32be(0) == 0x7f454c46 and

                                5 of ($sedexp_*)
}