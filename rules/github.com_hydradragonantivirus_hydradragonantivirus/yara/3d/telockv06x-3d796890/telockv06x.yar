rule tElockv06x : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 ?? ?? ?? ?? 60 E8 ?? ?? ?? ?? 58 83 C0 08 F3 EB FF }

	condition:
		$a0
}