rule BriefLzSig
{
		meta:
		author="_pusher_"
		date = "2015-11"
	strings: 
		$a0 = { 60 8B 74 24 24 8B 7C 24 28 FC AD 85 C0 74 4C 33 D2 8D 1C 38 A4 3B FB 73 42 E8 20 00 00 00 73 F4 E8 24 00 00 00 91 E8 1E }
	condition:
		($a0)
}