rule cobaltstrike_raw_payload_smb_stager_x86
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
	condition:
		
		uint32(@h01+0x00a1) == 0xe553a458 and
		uint32(@h01+0x00c4) == 0xd4df7045 and
		uint32(@h01+0x00d2) == 0xe27d6f28 and
		uint32(@h01+0x00f8) == 0xbb5f9ead and
		uint32(@h01+0x010d) == 0xbb5f9ead and
		uint32(@h01+0x0131) == 0xfcddfac0 and
		uint32(@h01+0x0139) == 0x528796c6 and
		uint32(@h01+0x014b) == 0x56a2b5f0
}