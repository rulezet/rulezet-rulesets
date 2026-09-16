rule MaskPE1xx
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 75 B7 81 F2 ?? ?? ?? ?? EB EB }
		$a1 = { B8 ?? ?? ?? ?? 50 EB 0F }

	condition:
		$a0 and $a1
}