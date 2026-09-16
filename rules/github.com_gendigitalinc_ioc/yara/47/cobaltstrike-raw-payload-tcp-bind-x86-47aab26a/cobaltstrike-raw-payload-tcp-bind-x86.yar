rule cobaltstrike_raw_payload_tcp_bind_x86
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
		uint32(@h01+0x00d5) == 0x6737dbc2 and
		uint32(@h01+0x00de) == 0xff38e9b7 and
		uint32(@h01+0x00e8) == 0xe13bec74 and
		uint32(@h01+0x00f1) == 0x614d6e75 and
		uint32(@h01+0x00fa) == 0x56a2b5f0 and
		uint32(@h01+0x0107) == 0x5fc8d902 and
		uint32(@h01+0x011a) == 0xe553a458 and
		uint32(@h01+0x0128) == 0x5fc8d902 and
		uint32(@h01+0x013d) == 0x614d6e75
}