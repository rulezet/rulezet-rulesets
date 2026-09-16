import "pe"
rule _MS_RunTime_Library_1990_10_
{
	meta:
		description = "MS Run-Time Library 1990 (10)"
	strings:
		$0 = {E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB}
	condition:
		$0 at pe.entry_point
}