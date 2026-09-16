rule xz_magic: info compress
{
        meta:
                author = "@h3x2b <tracker@h3x.eu>"
                description = "Detects XZ stream magics in ELF executable"

        strings:
		                $xz_00 = { fd 37 7a 58 }

		                $xz_01 = "YZB"

        condition:
                                uint32be(0) == 0x7f454c46 and

                                2 of ($xz_*)
}