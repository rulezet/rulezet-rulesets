rule cobaltstrike_raw_payload_tcp_reverse_x86
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
	condition:
		
		uint32(@h01+0x009c) == 0x0726774c and
		uint32(@h01+0x00ac) == 0x006b8029 and
		uint32(@h01+0x00bb) == 0xe0df0fea and
		uint32(@h01+0x00d5) == 0x6174a599 and
		uint32(@h01+0x00e5) == 0x56a2b5f0 and
		uint32(@h01+0x00f2) == 0x5fc8d902 and
		uint32(@h01+0x0105) == 0xe553a458 and
		uint32(@h01+0x0113) == 0x5fc8d902
}