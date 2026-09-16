import "pe"
rule upxpr10x
{
	meta:
		author = "PEiD"
		description = "UPX Protector 1.0x -> BlindAngel/TMG"
		group = "183"
		function = "0"
	strings:
		$a0 = { EB EC ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0 at pe.entry_point
}