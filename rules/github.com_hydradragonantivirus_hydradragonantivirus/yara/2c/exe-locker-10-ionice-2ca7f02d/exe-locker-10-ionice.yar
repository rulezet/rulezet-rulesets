import "pe"
rule _Exe_Locker_10__IonIce_
{
	meta:
		description = "Exe Locker 1.0 -> IonIce"
	strings:
		$0 = {E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00}
	condition:
		$0 at pe.entry_point
}