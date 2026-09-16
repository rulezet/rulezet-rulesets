import "pe"
rule pen3
{
	meta:
		author = "PEiD"
		description = "PEncrypt 3.0 -> junkcode"
		group = "142"
		function = "0"
	strings:
		$a0 = { E8 ?? ?? ?? ?? 5D 81 ED 05 10 40 ?? 8D B5 24 10 40 ?? 8B FE B9 0F ?? ?? ?? BB ?? ?? ?? ?? AD 33 C3 E2 FA }
	condition:
		$a0 at pe.entry_point
}