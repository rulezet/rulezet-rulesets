rule cobaltstrike_raw_payload_http_stager_x86
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 }
	condition:
		
		uint32(@h01+0x009c) == 0x0726774c and
		uint32(@h01+0x00aa) == 0xa779563a and
		uint32(@h01+0x00c6) == 0xc69f8957 and
		uint32(@h01+0x00de) == 0x3b2e55eb and
		uint32(@h01+0x00f2) == 0x7b18062d and
		uint32(@h01+0x010b) == 0x5de2c5aa and
		uint32(@h01+0x0114) == 0x315e2145 and
		uint32(@h01+0x0123) == 0x0be057b7 and
		uint32(@h01+0x02c4) == 0x56a2b5f0 and
		uint32(@h01+0x02d8) == 0xe553a458 and
		uint32(@h01+0x02f3) == 0xe2899612
}