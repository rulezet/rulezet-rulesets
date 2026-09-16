rule _MaskPE_16__yzkzero_
{
	meta:
		description = "MaskPE 1.6 -> yzkzero"
	strings:
		$0 = {36 81 2C 24 ?? ?? ?? 00 C3 60}
	condition:
		$0
}