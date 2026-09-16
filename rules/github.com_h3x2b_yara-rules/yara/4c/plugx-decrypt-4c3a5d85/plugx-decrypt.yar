rule plugx_decrypt : APT
{
    meta:
        description = "Detect constants used in the plugx decrypt function"
	author = "@h3x2b <tracker _AT h3x.eu>"
                                                                                                                        
    strings:
        $yes_v1 = { 31 F5 CD 1A }
        $yes_v2 = { F2 DC AF 2C }
        $yes_v3 = { 93 23 71 34 }
        $yes_v4 = { A4 C7 AD 46 }

    condition:
                uint16(0) == 0x5a4d

        and all of ( $yes_* )
}