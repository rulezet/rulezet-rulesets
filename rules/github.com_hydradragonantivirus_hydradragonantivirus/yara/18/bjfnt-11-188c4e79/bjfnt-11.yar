import "pe"
rule _BJFNT_11_
{
	meta:
		description = "BJFNT 1.1"
	strings:
		$0 = {EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 EB 01 C7 57 EB 01 C7 55 EB 02 CD 20 EB 02 C7 05 EB 01 EA EB 01 EA FC EB 01 EA E8 00 00 00 00 EB 01 C7 5E EB 02 CD 20 83 C6 50 EB 02 CD 20 8B FE EB 02 C7 05 B9 65 06 00 00 EB 02 C7}
	condition:
		$0 at pe.entry_point
}