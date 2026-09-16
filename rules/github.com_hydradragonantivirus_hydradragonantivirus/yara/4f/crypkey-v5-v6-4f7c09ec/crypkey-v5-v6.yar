import "pe"
rule _CrypKey_v5__v6_
{
	meta:
		description = "CrypKey v5 - v6"
	strings:
		$0 = {E8 B8 E8 90 02 83 F8 75 07 6A E8 FF 15 49 8F 40 A9 80 74}
	condition:
		$0 at pe.entry_point
}