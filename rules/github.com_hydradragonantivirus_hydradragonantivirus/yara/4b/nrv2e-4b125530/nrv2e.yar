rule Nrv2e
{
		meta:
		author="_pusher_"
		date = "2015-11"
		description = "www.oberhumer.com/opensource/ucl/"
	strings: 
		$a0 = { 55 8B EC 60 8B 75 08 8B 7D 0C 83 CD FF 31 C9 FC F9 E8 79 00 00 00 EB 06 A4 E8 6D 00 00 00 72 F8 31 C0 40 E8 63 00 00 00 }
	condition:
		$a0
}