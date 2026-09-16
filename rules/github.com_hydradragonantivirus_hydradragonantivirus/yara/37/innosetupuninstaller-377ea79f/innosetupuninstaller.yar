rule InnoSetupUnInstaller : Jordan Russel
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 12 55 6E 69 6E 73 74 50 72 6F 67 72 65 73 73 46 6F 72 6D }
	condition:
		uint32(0x30) == 0x6E556E49 and $a0
}