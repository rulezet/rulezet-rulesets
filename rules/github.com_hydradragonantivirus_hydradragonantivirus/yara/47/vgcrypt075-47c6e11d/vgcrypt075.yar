import "pe"
rule vgcrypt075
{
	meta:
		author = "PEiD"
		description = "Virogen Crypt 0.75"
		group = "187"
		function = "0"
	strings:
		$a0 = { 9C 55 E8 EC ?? ?? ?? 87 D5 5D 60 87 D5 80 BD 15 27 40 ?? 01 }
	condition:
		$a0 at pe.entry_point
}