import "pe"
rule _BGI_Stroked_Font_v11_
{
	meta:
		description = "BGI Stroked Font v.1.1"
	strings:
		$0 = {50 4B 08 08 42 47 49 20 53 74 72 6F 6B 65 64 20 46 6F 6E 74 20 56 31 2E 31}
	condition:
		$0 at pe.entry_point
}