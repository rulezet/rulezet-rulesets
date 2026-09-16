import "pe"
rule _NoodleCrypt_v20_
{
	meta:
		description = "NoodleCrypt v2.0"
	strings:
		$0 = {55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 ?? FF 15 60 70 40 ?? BF C0 B2 40 ?? 68 04 01 ?? ?? 57 50 A3 AC B2 40 ?? FF 15 4C 70 40 ?? 56 56 6A 03 56 6A 01 68 ?? ?? ??}
	condition:
		$0 at pe.entry_point
}