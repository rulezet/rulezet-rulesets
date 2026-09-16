rule cobaltstrike_raw_payload_smb_stager_x86_utf16
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }
	condition:
		uint32(@h01+0x0145) == 0xe5005300 and
		uint32(@h01+0x018b) == 0xd400df00 and
		uint32(@h01+0x01a7) == 0xe2007d00 and
		uint32(@h01+0x01f3) == 0xbb005f00 and
		uint32(@h01+0x021d) == 0xbb005f00 and
		uint32(@h01+0x0265) == 0xfc00dd00 and
		uint32(@h01+0x0275) == 0x52008700 and
		uint32(@h01+0x0299) == 0x5600a200
}