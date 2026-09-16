rule sedexp_lkm: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects sedexp samples - 202408 - possible sedexp linux kernel module"
                                		
        strings:
                $sedexp_00 = "sedexp"

        condition:
                                		                uint32(0) == 0x587a37fd and

                                1 of ($sedexp_*)
}