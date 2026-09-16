rule cobaltstrike_raw_payload_http_stager_x64
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC 48 83 E4 F0 E8 C8 00 00 00 41 51 41 50 52 51 56 48 31 D2 65 48 8B 52 }
	condition:
		
		uint32(@h01+0x00e9) == 0x0726774c and
		uint32(@h01+0x0101) == 0xa779563a and
		uint32(@h01+0x0120) == 0xc69f8957 and
		uint32(@h01+0x013f) == 0x3b2e55eb and
		uint32(@h01+0x0163) == 0x7b18062d and
		uint32(@h01+0x0308) == 0x56a2b5f0 and
		uint32(@h01+0x0324) == 0xe553a458 and
		uint32(@h01+0x0342) == 0xe2899612
}