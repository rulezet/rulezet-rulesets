rule Win_Spyware_Banker_2690
{
strings:
	$a0 = { e424f0b7eccd4a6618ebfff2f4451ae6327a7d84bdee9dc8051c3c3aecca43d0b6f4a2a1f5e169070365e2b7a548d7a633ef77c0cf45e22d2938a28da4b17f914be32e9680d328dc8d12a4acbb04 }


condition:
	$a0
}