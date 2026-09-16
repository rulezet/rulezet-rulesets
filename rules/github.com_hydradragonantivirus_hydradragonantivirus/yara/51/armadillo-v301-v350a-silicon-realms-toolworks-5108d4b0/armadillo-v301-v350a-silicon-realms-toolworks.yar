import "pe"
rule _Armadillo_v301__v350a__Silicon_Realms_Toolworks_
{
	meta:
		description = "Armadillo v3.01 - v3.50a -> Silicon Realms Toolworks"
	strings:
		$0 = {60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 ?? 87 DB 7A F0 ?? ?? 61 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 60 9C 33 C0 E8 09 00 00 00 E8 E8 23 00 00 00 7A 23 ?? 8B 04 24 EB 03 7A 29 ?? C6 00 90 C3 ?? 70 F0 87 D2 71 07 ?? ?? 40 8B DB 7A 11 EB 08 ?? EB F7 EB C3 ?? 7A E9 70 DA 7B D1 71 F3 ?? 7B F3 71 D6 ?? 9D 61 83 ED 06 33 FF 47 60 33 C9 75 02 EB 15 ?? 33 C9 75 18 7A 0C 70 0E EB 0D ?? 72 0E 79 F1 ?? ?? ?? 79 09 74 F0 EB 87 ?? 7A F0 ?? ?? 61 8B 9C BD B8 43}
	condition:
		$0 at pe.entry_point
}