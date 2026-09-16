rule info_nop_sled
{
	meta:
		description = "Identify a large region of nop'd bytes."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.03.07"
		DaysofYARA = "66/100"

	strings:
				$nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		(
			int16(0) == 0x5a4d or      			uint32(0) == 0x464c457f or 			uint32(0) == 0xfeedface or 			uint32(0) == 0xcefaedfe or 			uint32(0) == 0xfeedfacf or 			uint32(0) == 0xcffaedfe or 			uint32(0) == 0xcafebabe or 			uint32(0) == 0xbebafeca    		) and
		any of them
}