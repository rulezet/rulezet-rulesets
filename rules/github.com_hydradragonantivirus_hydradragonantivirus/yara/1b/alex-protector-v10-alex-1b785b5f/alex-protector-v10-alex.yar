import "pe"
rule _Alex_Protector_v10__Alex_
{
	meta:
		description = "Alex Protector v1.0 -> Alex"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B}
	condition:
		$0 at pe.entry_point
}