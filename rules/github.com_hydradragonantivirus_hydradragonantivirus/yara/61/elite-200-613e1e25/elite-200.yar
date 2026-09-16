import "pe"
rule _Elite_200_
{
	meta:
		description = "Elite 2.00"
	strings:
		$0 = {FC 8C C8 01 06 00 00 BA 00 00 03 C2 8B D8 05 00 00 8E DB 8E C0 33 FF 33 F6 B9 08 00 F3 A5 48 4B 4A 75 EE}
	condition:
		$0 at pe.entry_point
}