import "pe"
rule upxm
{
	meta:
		author = "PEiD"
		description = "UPX MODifier 0.1x -> snaker"
		group = "183"
		function = "0"
	strings:
		$a0 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
	condition:
		$a0 at pe.entry_point
}