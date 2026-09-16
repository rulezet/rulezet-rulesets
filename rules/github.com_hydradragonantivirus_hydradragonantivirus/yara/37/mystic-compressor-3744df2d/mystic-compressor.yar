import "pe"
rule Mystic_Compressor : UnKnownVer
{
		meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 43 6D 44 49 41 4C 33 32 00 00 00 00 }
		$a1 = { 44 65 6C 70 68 69 41 70 70 6C 69 63 61 74 69 6F 6E }
	condition:
		pe.imports ("kernel32.dll","VirtualAlloc") and
		pe.imports ("kernel32.dll","GetStartupInfoA") and
		pe.imports ("kernel32.dll","OutputDebugStringA") and
		pe.imports ("kernel32.dll","LoadLibraryA") and
		($a0 in (pe.sections[1].raw_data_offset..pe.sections[2].raw_data_offset+pe.sections[2].raw_data_size)) and 
		$a1
}