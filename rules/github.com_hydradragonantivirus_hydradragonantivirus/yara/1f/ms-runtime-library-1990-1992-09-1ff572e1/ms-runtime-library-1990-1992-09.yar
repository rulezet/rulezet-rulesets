import "pe"
rule _MS_RunTime_Library_1990_1992_09_
{
	meta:
		description = "MS Run-Time Library 1990, 1992 (09)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E}
	condition:
		$0 at pe.entry_point
}