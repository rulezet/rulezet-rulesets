import "pe"
rule upxs
{
	meta:
		author = "PEiD"
		description = "UPX-Scrambler RC1.x -> ?OnT?oL"
		group = "183"
		function = "0"
	strings:
		$a0 = { 90 61 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
	condition:
		$a0 at pe.entry_point
}