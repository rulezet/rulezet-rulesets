import "pe"
rule _Exe_Locker_v10__IonIce_
{
	meta:
		description = "Exe Locker v1.0 --> IonIce"
	strings:
		$0 = {E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00}
	condition:
		$0 at pe.entry_point
}