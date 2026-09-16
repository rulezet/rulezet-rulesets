import "pe"
rule _vprotector_13__vcasm_
{
	meta:
		description = "vprotector 1.3 -> vcasm"
	strings:
		$0 = {E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68}
	condition:
		$0 at pe.entry_point
}