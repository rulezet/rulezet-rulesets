import "pe"
rule pep
{
	meta:
		author = "PEiD"
		description = "PE Packer -> Vecna"
		group = "153"
		function = "0"
	strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }
	condition:
		$a0 at pe.entry_point
}