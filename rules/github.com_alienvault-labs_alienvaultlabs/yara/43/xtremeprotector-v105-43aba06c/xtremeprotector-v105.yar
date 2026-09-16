rule _XtremeProtector_v105_
{
	meta:
		description = "Xtreme-Protector v1.05"
	strings:
		$0 = {B8 ?? B9 75 ?? 50 51 E8 05 ?? ?? ?? E9 4A 01 ?? ?? 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 ?? ?? ?? 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46}
	condition:
		$0 at entrypoint
}