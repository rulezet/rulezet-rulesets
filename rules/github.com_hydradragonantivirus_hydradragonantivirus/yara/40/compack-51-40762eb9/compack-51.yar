import "pe"
rule _COMPACK_51_
{
	meta:
		description = "COMPACK 5.1"
	strings:
		$0 = {BD 00 00 50 06 8C CB 03 DD 8C D2 4B 8E DB BE 4A 00 BF 00 07 8E C2 B9 08 00 F3 A5 4A 4D 75 EC 8B F7 8E DA 0E 07 06 16 BF 63 06 57 33 FF F9 CB 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 31 20 57 20 43 6F 6C 6C 69 73 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}