rule lang_zig
{
	meta:
		description = "Identify a Zig binary regardless of format (PE, Macho, ELF) or arch. Tested with regular and stripped binaries."
		author = "@shellcromancer"
		version = "1.0"
		date = "2023.01.04"
		sample = "ae3beacdfaa311d48d9c776ddd1257a6aad2b0fe" 		DaysofYARA = "4/100"

	strings:
		$zig = "zig"

	condition:
		(
			int16(0) == 0x5a4d or      			uint32(0) == 0x464c457f or 			uint32(0) == 0xfeedface or 			uint32(0) == 0xcefaedfe or 			uint32(0) == 0xfeedfacf or 			uint32(0) == 0xcffaedfe or 			uint32(0) == 0xcafebabe or 			uint32(0) == 0xbebafeca    		) and
		#zig >= 4
}