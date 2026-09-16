rule VMProtectSDK : VMProtect Software
{
	meta:
		author="_pusher_"
		date = "2016-08"
	strings:
		$aa0 = { 9C 9C 9C 8D 64 24 ?? E9 }
		$aa1 = { 9C 9C 9C ( 8F | 89 | C7 ) ( 44 | 4C | 6C ) 24 ?? ( E9 | E8 | 68 | 88 | C6 | 60 | 6E  | FF ) }
		$aa2 = { 9C 9C F3 9C 8F 44 24 ?? E8 }
		$aa3 = { 9C 9C 9C FF 74 24 ?? ( 8D | 8F ) }
		$aa4 = { 9C 9C 88 44 24 ?? 8B }
		$aa5 = { 9C 9C 8D 64 24 ?? ( E9 | 0F ) }
		$aa6 = { 9C 9C 9C E8 ?? ?? 00 00 }
		$aa7 = { 9C 9C 9C 68 ?? ?? ?? ?? 89 }
				$aa8 = { E9 ?? ?? ( 00 00 | FF FF ) ( 9C | F3 9C ) E9 ?? ?? ( 00 00 | FF FF ) ( E9 ?? ?? 00 00 | (56 | 57) ) }
	condition:
				uint16(0) == 0x5A4D and
				uint32(uint32(0x3C)) == 0x00004550 and
		any of ($aa*)
		
}