import "pe"
rule _MS_RunTime_Library_1992_13_
{
	meta:
		description = "MS Run-Time Library 1992 (13)"
	strings:
		$0 = {BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21}
	condition:
		$0 at pe.entry_point
}