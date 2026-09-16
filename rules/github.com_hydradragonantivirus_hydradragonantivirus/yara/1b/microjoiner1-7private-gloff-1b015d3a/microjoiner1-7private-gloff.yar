rule MicroJoiner1_7Private__GlOFF
{
	meta:
		author = "PEiD"
		description = "MicroJoiner 1.7 Private -> GlOFF"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 90 BF F7 FF FF FF 87 D2 90 BF F7 FF FF FF BF 2F 10 40 00 87 D2 90 87 D2 8D 5F 21 87 D2 6A 0A 87 D2 58 6A 04 87 D2 59 60 87 D2 57 87 D2 E8 AC 00 00 00 90 95 8B 55 3C 87 D2 8B 74 2A 78 87 D2 8D 74 2E 18 AD 87 D2 91 87 D2 AD 50 87 D2 AD 03 C5 87 D2 92 87 D2 AD 03 C5 50 87 D2 8B F2 AD 03 C5 33 D2 87 D2 C1 C2 03 87 D2 32 10 40 87 D2 80 38 00 75 EF 8B 04 24 87 D2 83 04 24 02 8B FB 87 D2 }
	condition:
		$a0
}