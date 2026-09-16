import "pe"
rule _Netopsystems_FEAD_Optimizer_3_
{
	meta:
		description = "Netopsystems FEAD Optimizer 3"
	strings:
		$0 = {E8 00 00 00 00 58 BB 00 00 40 00 8B ?? ?? ?? 00 00}
	condition:
		$0 at pe.entry_point
}