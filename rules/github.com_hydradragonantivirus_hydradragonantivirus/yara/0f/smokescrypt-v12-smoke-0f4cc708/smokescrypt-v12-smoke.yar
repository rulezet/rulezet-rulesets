import "pe"
rule _SmokesCrypt_v12__Smoke_
{
	meta:
		description = "SmokesCrypt v1.2 -> Smoke"
	strings:
		$0 = {60 B8 ?? ?? ?? 00 B8 ?? ?? ?? 00 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1}
	condition:
		$0 at pe.entry_point
}