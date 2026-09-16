import "pe"
rule _ASPack_102b_or_10803_
{
	meta:
		description = "ASPack 1.02b or 1.08.03"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED}
	condition:
		$0 at pe.entry_point
}