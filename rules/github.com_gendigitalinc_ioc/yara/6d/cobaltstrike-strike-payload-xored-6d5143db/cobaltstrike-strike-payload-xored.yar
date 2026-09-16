rule cobaltstrike_strike_payload_xored
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
		$h01 = { 10 ?? 00 00 ?? ?? ?? 00 ?? ?? ?? ?? 61 61 61 61 }
	condition:
				uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFCE88900 or
				uint32be(@h01+8) ^ uint32be(@h01+16) == 0xFC4883E4 or
				uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5AE800 or
				uint32be(@h01+8) ^ uint32be(@h01+16) == 0x4D5A4152 or
				uint32be(@h01+8) ^ uint32be(@h01+16) == 0x90909090
}