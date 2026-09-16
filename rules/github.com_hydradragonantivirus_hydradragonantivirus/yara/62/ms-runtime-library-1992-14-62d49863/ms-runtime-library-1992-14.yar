import "pe"
rule _MS_RunTime_Library_1992_14_
{
	meta:
		description = "MS Run-Time Library 1992 (14)"
	strings:
		$0 = {1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30}
	condition:
		$0 at pe.entry_point
}