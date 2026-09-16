rule UPXLock : CyberDoom
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { B2 ?? 8D B5 ?? ?? ?? ?? 8B FE B9 12 03 00 00 AC 32 C2 AA E2 FA C3 }
	condition:
		$a0
}