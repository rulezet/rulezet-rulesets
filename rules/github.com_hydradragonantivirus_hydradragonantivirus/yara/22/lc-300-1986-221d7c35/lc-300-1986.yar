import "pe"
rule _LC_300_1986_
{
	meta:
		description = "LC 3.00 (1986)"
	strings:
		$0 = {FA B8 00 00 05 10 00 B1 04 D3 E8 8C CB 03 C3 8E D8 8E D0}
	condition:
		$0 at pe.entry_point
}