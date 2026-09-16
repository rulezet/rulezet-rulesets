import "pe"
rule Morphine : Holy_Father Ratter29A
{
	meta:
		author="_pusher_"
		date = "2015-11"
		description="Polymorphic Cryptor"
	condition:
		(pe.number_of_sections>=2) and
		(uint32(uint32(0x3C)+0x84) == 0x00000200) and
		pe.sections[0].raw_data_offset == 0x00000400 and
		pe.sections[1].virtual_size == 0x00001000 and
				(uint32(pe.sections[1].raw_data_offset+0x4E) == 0x50746547) and
				pe.imports ("kernel32.dll","GetProcAddress") and
		pe.imports ("kernel32.dll","LoadLibraryA")
}