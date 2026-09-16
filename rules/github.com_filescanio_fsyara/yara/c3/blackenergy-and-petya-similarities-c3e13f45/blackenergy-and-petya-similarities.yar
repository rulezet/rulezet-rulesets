rule blackenergy_and_petya_similarities : hardened
{
	meta:
		author = "Kaspersky"
		source = "https://securelist.com/from-blackenergy-to-expetr/78937/"
		score = 60

	strings:
		$bytes00 = { 73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00 }
		$bytes01 = { 43 00 6f 00 6d 00 53 00 70 00 65 00 63 00 }
		$bytes02 = { 49 6e 69 74 69 61 74 65 53 79 73 74 65 6d 53 68 75 74 64 6f 77 6e 45 78 57}
		$bytes03 = { 68 ?? ?? ?1 ?0 ff 15 ?? ?? ?? ?0 3b c7 74 ?? }
		$bytes04 = { 2f 00 63 00 }
		$hex_string = { b9 ?? ?? ?1 ?0 8d 44 24 ?c 66 8b 10 66 3b 11 75 1e 66
                        85 d2 74 15 66 8b 50 02 66 3b 51 02 75 0f 83 c0 04 83 c1 04 66 85 d2 75
                        de 33 c0 eb 05 1b c0 83 d8 ff 85 c0 0f 84 ?? 0? 00 00 b9 ?? ?? ?1 ?0 8d
                        44 24 ?c 66 8b 10 66 3b 11 75 1e 66 85 d2 74 15 66 8b 50 02 66 3b 51 02
                        75 0f 83 c0 04 83 c1 04 66 85 d2 75 de 33 c0 eb 05 1b c0 83 d8 ff 85 c0
                        0f 84 ?? 0? 00 00 }

	condition:
		(( uint16( 0 ) == 0x5A4D ) ) and ( filesize < 5000000 ) and ( all of them )
}