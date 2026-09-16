import "pe"
rule _PE_password_protector_by_SMT_
{
	meta:
		description = "PE password protector by SMT"
	strings:
		$0 = {E8 04 00 00 00 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 00 81 EF 00 00 00 00 83 EF 05 89 AD 88 27 40 00 8D 9D 07 29 40 00 8D B5 62 28 40 00 46 80 3E 00 74 24 56 FF 95 9D 29 40 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 A1 29 40}
	condition:
		$0 at pe.entry_point
}