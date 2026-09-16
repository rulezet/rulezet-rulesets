rule dUP2 : diablo2oo2
{
	meta:
		author="_pusher_"
		date = "2015-12"
	strings:
		$a0 = { 89 7D F8 68 EF BE AD DE FF 75 F4 FF 75 F8 E8 3F FF FF FF }
		$a1 = { 55 8B EC 56 57 53 8B 75 08 8B FE 8B 5D 10 8B 4D 0C EB 0D AC 8A D0 32 C3 AA D1 CB 32 DA 03 D9 49 0B C9 75 EF 5B 5F 5E C9 C2 0C 00 E8 07 00 00 00 6A 00 E8 05 01 00 00 }
	condition:
		$a0 and $a1
}