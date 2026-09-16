rule sedexp_lkm_hiding: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects sedexp samples - 202408 - fiddling with the linux kernel modules"
                                		
        strings:
                $sedexp_00 = "retpoline=Y"
                $sedexp_01 = "license=GPL"
                $sedexp_02 = "intree=Y"
                $sedexp_03 = "module_layout"

        condition:
                                uint32be(0) == 0x7f454c46 and

                                4 of ($sedexp_*)
}