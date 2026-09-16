rule Win_Trojan_SdBot_3683
{
strings:
	$a0 = { 056fc87bc8ae6c25ca0268debfe57cb96f28306d4f612b10030b3d047d1d0ad5b49d74e8fd827e4b1415df4ee90a685a8a0f2b5e7d60fa688972fb6e81d7a33c3286d149c93527f45bdf9e12a59d }


condition:
	$a0
}