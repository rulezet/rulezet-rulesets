rule cobaltstrike_raw_payload_tcp_reverse_x64_utf16
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { FC 00 48 00 83 00 E4 00 F0 00 E8 00 C8 00 00 00 00 00 00 00 41 00 51 00 41 00 50 00 52 00 51 00 56 00 48 00 31 00 D2 00 65 00 48 00 8B 00 52 }
	condition:
		uint32(@h01+0x0203) == 0x07002600 and
		uint32(@h01+0x0225) == 0x00006b00 and
		uint32(@h01+0x025d) == 0xe000df00 and
		uint32(@h01+0x0287) == 0x61007400 and
		uint32(@h01+0x02d9) == 0x5f00c800 and
		uint32(@h01+0x0319) == 0xe5005300 and
		uint32(@h01+0x034d) == 0x5f00c800 and
		uint32(@h01+0x0385) == 0x61004d00
}