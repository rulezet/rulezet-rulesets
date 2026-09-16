rule kkrunchy_023_alpha_2
{
	meta:
		author = "PEiD"
		description = "kkrunchy 0.23 alpha 2 -> Ryd"
		group = "444"
		function = "0"
	strings:
		$a0 = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
	condition:
		$a0
}