import "pe"
rule _Private_EXE_v20a_
{
	meta:
		description = "Private EXE v2.0a"
	strings:
		$0 = {EB CD CD EB EB EB EB CD E8 E9 50}
		$1 = {E8 58 83 D8 05 89 C3 81 C3 8B 43 64}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}