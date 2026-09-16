import "pe"
rule lamecrypt
{
	meta:
		author = "PEiD"
		description = "LameCrypt -> LaZaRus"
		group = "130"
		function = "0"
	strings:
		$a0 = { 60 66 9C BB ?? ?? ?? ?? 80 B3 ?? 10 40 ?? 90 4B 83 FB FF 75 F3 66 9D 06 }
	condition:
		$a0 at pe.entry_point
}