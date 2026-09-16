rule tElockv092b1 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 87 E9 FF FF ?? ?? ?? B8 }
	condition:
		$a0
}