import "pe"
rule _Safedisc_V450000__Macrovision_Corporation__SignByfly__20080117_
{
	meta:
		description = "Safedisc V4.50.000 -> Macrovision Corporation * Sign.By.fly * 20080117"
	strings:
		$0 = {55 8B EC 60 BB 6E ?? ?? ?? B8 0D ?? ?? ?? 33 C9 8A 08 85 C9 74 0C B8 E4 ?? ?? ?? 2B C3 83 E8 05 EB 0E 51 B9 2B ?? ?? ?? 8B C1 2B C3 03 41 01 59 C6 03 E9 89 43 01 51 68 D9 ?? ?? ?? 33 C0 85 C9 74 05 8B 45 08 EB 00 50 E8 25 FC FF FF 83 C4 08 59 83 F8 00 74 1C C6 03 C2 C6 43 01 0C 85 C9 74 09 61 5D B8 00 00 00 00 EB 96 50 B8 F9 ?? ?? ?? FF 10 61 5D EB 47 80 7C 24 08 00 75 40 51 8B 4C 24 04 89 0D ?? ?? ?? ?? B9 02 ?? ?? ?? 89 4C 24 04 59 EB 29 50 B8 FD ?? ?? ?? FF 70 08 8B 40 0C FF D0 B8 FD ?? ?? ?? FF 30 8B 40 04 FF D0 58 B8 25 ?? ?? ?? FF 30 C3 72 16 61 13 60 0D E9 ?? ?? ?? ?? 66 83 3D ?? ?? ?? ?? ?? 74 05 E9 91 FE FF FF C3}
	condition:
		$0 at pe.entry_point
}