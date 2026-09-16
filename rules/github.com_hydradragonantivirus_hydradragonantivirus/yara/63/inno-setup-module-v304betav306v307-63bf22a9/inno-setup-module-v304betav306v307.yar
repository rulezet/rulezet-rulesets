rule _Inno_Setup_Module_v304betav306v307_
{
	meta:
		description = "Inno Setup Module v3.0.4-beta/v3.0.6/v3.0.7"
	strings:
		$0 = {55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C}
	condition:
		$0
}