import "pe"
rule _Vx_August_16th_Iron_Maiden_
{
	meta:
		description = "Vx: August 16th (Iron Maiden)"
	strings:
		$0 = {BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02}
	condition:
		$0 at pe.entry_point
}