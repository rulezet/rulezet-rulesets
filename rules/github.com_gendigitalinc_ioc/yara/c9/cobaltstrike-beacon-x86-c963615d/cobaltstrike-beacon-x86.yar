rule cobaltstrike_beacon_x86
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
				$h01 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 ?? ?? ?? ?? FF D3 68 }
				$h11 = { 00 01 00 01 00 02 ?? ?? 00 02 00 01 00 02 ?? ?? 00 }
				$h12 = { 69 68 69 68 69 6B ?? ?? 69 6B 69 68 69 6B ?? ?? 69 }
				$h13 = { 2E 2F 2E 2F 2E 2C ?? ?? 2E 2C 2E 2F 2E 2C ?? ?? 2E }
	condition:
		$h01 and
		any of ($h1*)
}