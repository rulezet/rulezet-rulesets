import "pe"
rule estealth1x
{
	meta:
		author = "PEiD"
		description = "EXEStealth 1.x - 2.x -> WebtoolMaster"
		group = "119"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? B9 7B 09 00 00 8D BD ?? ?? ?? ??  8B F7 AC }
	condition:
		$a0 at pe.entry_point
}