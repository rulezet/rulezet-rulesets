import "pe"
rule _EXE_joiner__Amok_
{
	meta:
		description = "EXE joiner -> Amok"
	strings:
		$0 = {A1 14 A1 40 00 C1 E0 02 A3 18 A1 40}
	condition:
		$0 at pe.entry_point
}