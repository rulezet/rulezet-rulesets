import "pe"
rule _ACProtect_V14X__risco_
{
	meta:
		description = "ACProtect V1.4X -> risco"
	strings:
		$0 = {60 E8 01 00 00 00 7C 83 04 24 06 C3}
	condition:
		$0 at pe.entry_point
}