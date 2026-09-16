rule Unpacked_ap0x
{
		meta:
		author="_pusher_"
		date = "2015-11"
		description="File unpacked with ap0x unpacker"
	strings:
		$a0 = { 4D 5A 40 00 01 00 00 00 02 00 04 00 FF FF 02 00 40 00 00 00 0E 00 00 00 1C 00 00 00 00 00 00 00 57 69 6E 33 32 20 6F 6E 6C 79 21 0D 0A 24 0E B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 }
		$a1 = { 2E 61 70 30 78 }
	condition:
		$a0 at 0 and
		$a1
}