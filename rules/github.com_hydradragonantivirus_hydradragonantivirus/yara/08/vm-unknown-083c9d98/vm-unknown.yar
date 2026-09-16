rule VM_Unknown
{
	meta:
		author="_pusher_"
		date = "2017-05"
	strings:
				$aa0 = { E9 ?? ?? ?? ?? ( 2E | 3E | F3 ) CC E9 }
			condition:
				uint16(0) == 0x5A4D and
				uint32(uint32(0x3C)) == 0x00004550 and
		any of ($aa*)
		
}