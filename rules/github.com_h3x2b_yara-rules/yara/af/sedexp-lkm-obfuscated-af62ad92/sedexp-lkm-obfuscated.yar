rule sedexp_lkm_obfuscated: malware linux
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects sedexp samples - 202408 - fiddling with the linux kernel modules"
                                				
        strings:
		                $sedexp_00 = { 48 b8 72 65 74 70 6f 6c 69 6e }

		                $sedexp_01 = { c7 42 ?? 65 3d 59 }


		                $sedexp_02 = { 48 b8 6c 69 63 65 6e 73 65 3d }

				$sedexp_03 = { c7 42 ?? 47 50 4c }

        condition:
                                uint32be(0) == 0x7f454c46 and

                                3 of ($sedexp_*)
}