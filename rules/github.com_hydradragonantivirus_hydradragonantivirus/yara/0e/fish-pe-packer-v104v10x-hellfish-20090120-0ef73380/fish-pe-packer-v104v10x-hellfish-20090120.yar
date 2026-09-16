import "pe"
rule _Fish_Pe_Packer_V104V10X__hellfish__20090120_
{
	meta:
		description = "Fish Pe Packer V1.04-V1.0X -> hellfish * 20090120"
	strings:
		$0 = {60 B8 ?? ?? ?? ?? FF D0 5A 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 57 56 53 55 89 E5 8B 45 20 01 45 24 50 FC 8B 75 18 01 75 1C 56 8B 75 14 AD 92 52 8A 4E FE 83 C8 FF D3 E0 F7 D0 50 88 F1 83 C8 FF D3 E0 F7 D0 50 00 D1 89 F7 83 EC 0C 29 C0 40 50 50 50 50 50 57 AD 89 C1 AD 29 F6 56 83 CB FF F3 AB 6A 05 59 E8 9C 02 00 00 E2 F9 8D 36 8D 3F 8B 7D FC 8B 45 F0 2B 7D 20 21 F8 89 45 E8}
	condition:
		$0 at pe.entry_point
}