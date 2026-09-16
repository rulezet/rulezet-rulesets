rule tElockv03 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 66 8B C0 8D 24 24 60 9C E8 ?? ?? ?? ?? 5D D1 4D 12 81 6D 2A 79 AD 6C 4D EB 02 ?? ?? 8D B5 EC 01 }

	condition:
		$a0
}