import "pe"
rule _PELOCKnt_204_
{
	meta:
		description = "PELOCKnt 2.04"
	strings:
		$0 = {EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60}
	condition:
		$0 at pe.entry_point
}