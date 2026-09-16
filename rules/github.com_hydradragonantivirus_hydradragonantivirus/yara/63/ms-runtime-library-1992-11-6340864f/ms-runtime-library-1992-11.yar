import "pe"
rule _MS_RunTime_Library_1992_11_
{
	meta:
		description = "MS Run-Time Library 1992 (11)"
	strings:
		$0 = {B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5}
	condition:
		$0 at pe.entry_point
}