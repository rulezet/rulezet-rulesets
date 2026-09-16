import "pe"
rule _PE_Password_v02_SMTSMF__SMT_
{
	meta:
		description = "PE Password v0.2 SMT/SMF -> SMT"
	strings:
		$0 = {E8 04 00 00 00 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 00 81 EF ?? ?? ?? ?? 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80}
	condition:
		$0 at pe.entry_point
}