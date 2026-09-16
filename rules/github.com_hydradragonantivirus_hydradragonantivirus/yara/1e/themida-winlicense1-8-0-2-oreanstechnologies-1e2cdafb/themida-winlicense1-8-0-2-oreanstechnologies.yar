rule Themida_WinLicense1_8_0_2___OreansTechnologies
{
	meta:
		author = "PEiD"
		description = "Themida/WinLicense 1.8.0.2 +  -> Oreans Technologies"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }
	condition:
		$a0
}