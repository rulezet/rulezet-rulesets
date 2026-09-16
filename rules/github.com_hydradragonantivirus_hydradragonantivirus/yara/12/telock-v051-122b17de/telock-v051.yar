import "pe"
rule _tElock_v051_
{
	meta:
		description = "tElock v0.51"
	strings:
		$0 = {C1 EE ?? 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 ?? ?? ?? ?? 5E 83 C6 8B FE 68 79 01 59 EB}
	condition:
		$0 at pe.entry_point
}