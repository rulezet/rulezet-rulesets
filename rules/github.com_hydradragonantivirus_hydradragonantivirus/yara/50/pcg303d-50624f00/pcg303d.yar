import "pe"
rule pcg303d
{
	meta:
		author = "PEiD"
		description = "PC-Guard 3.00 - 4.02 -> Blagoje Ceklic"
		group = "135"
		function = "0"
	strings:
		$a0 = { 55 50 E8 ?? ?? ?? ?? 5D EB 01 E3 60 E8 03 ?? ?? ?? D2 EB 0B 58 EB 01 48 40 EB 01 }
	condition:
		$a0 at pe.entry_point
}