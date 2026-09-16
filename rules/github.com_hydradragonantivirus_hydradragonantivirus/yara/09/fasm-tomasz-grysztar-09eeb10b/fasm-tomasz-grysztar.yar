import "pe"
rule _fasm__Tomasz_Grysztar_
{
	meta:
		description = "fasm -> Tomasz Grysztar"
	strings:
		$0 = {53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00}
		$1 = {6A 24}
		$2 = {6A 00}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point or $2 at pe.entry_point
}