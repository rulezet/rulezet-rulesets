import "pe"
rule Parite_PE_Virus : Might_Be_Malware
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 98 05 00 00 }
	condition:
		pe.sections[pe.section_index(pe.entry_point)].name contains "\x07" and
		pe.sections[pe.section_index(pe.entry_point)].name contains "." and
		($a0 in (pe.entry_point..pe.entry_point+0x50))
}