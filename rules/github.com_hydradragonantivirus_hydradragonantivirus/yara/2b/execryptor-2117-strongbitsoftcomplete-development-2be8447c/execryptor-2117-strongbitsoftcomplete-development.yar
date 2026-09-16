rule _EXECryptor_2117__StrongbitSoftComplete_Development_
{
	meta:
		description = "EXECryptor 2.1.17 -> Strongbit/SoftComplete Development"
	strings:
		$0 = {BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01}
	condition:
		$0
}