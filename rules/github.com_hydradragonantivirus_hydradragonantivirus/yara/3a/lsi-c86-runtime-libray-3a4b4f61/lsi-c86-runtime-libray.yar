import "pe"
rule _LSI_C86_RunTime_Libray_
{
	meta:
		description = "LSI C-86 Run-Time Libray"
	strings:
		$0 = {B8 ?? ?? 8E C0 06 17 BC ?? ?? 26 8C ?? ?? ?? B4 30 CD 21 26 A3 ?? ?? FC}
	condition:
		$0 at pe.entry_point
}