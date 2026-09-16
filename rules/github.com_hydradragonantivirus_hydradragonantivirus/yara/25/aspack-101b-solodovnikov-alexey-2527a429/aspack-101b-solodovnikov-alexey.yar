import "pe"
rule _ASPack_101b__Solodovnikov_Alexey_
{
	meta:
		description = "ASPack 1.01b -> Solodovnikov Alexey"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED D2 2A 44 00 B8 CC 2A 44 00 03 C5 2B 85 A5 2E 44 00 89 85 B1 2E 44 00 80 BD 9C 2E 44}
	condition:
		$0 at pe.entry_point
}