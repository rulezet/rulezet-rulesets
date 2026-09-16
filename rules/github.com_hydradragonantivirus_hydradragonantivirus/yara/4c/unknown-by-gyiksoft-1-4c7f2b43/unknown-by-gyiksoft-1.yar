import "pe"
rule _unknown_by_GyikSoft_1_
{
	meta:
		description = "unknown by GyikSoft 1"
	strings:
		$0 = {8C C9 81 C1 00 00 51 B9 00 00 51 00 00 00 00 00 00 06 00 00 00 00 00 83 EB 18 53 51 B8 00 00 8C CA 03 D0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 79 EE 00 00 00 00 00 00 BE 00 00 CB}
	condition:
		$0 at pe.entry_point
}