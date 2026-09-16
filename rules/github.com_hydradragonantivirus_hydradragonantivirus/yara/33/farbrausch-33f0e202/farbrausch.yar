import "pe"
rule farbrausch
{
	meta:
		author = "PEiD"
		description = "UPX Modified Stub -> Farb-rausch Consumer Consulting"
		group = "122"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF FC B2 80 A4 E8 }
	condition:
		$a0 at pe.entry_point
}