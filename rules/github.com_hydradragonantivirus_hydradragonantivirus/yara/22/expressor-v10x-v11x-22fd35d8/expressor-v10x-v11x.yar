import "pe"
rule _eXpressor_v10x__v11x_
{
	meta:
		description = "eXpressor v1.0x / v1.1x"
	strings:
		$0 = {55 8B EC 81 EC D4 01 ?? ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E}
	condition:
		$0 at pe.entry_point
}