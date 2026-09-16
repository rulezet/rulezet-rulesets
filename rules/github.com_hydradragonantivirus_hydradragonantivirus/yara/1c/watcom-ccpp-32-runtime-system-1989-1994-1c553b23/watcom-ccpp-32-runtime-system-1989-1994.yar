import "pe"
rule _WATCOM_CCpp_32_RunTime_System_1989_1994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1989, 1994"
	strings:
		$0 = {0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72}
	condition:
		$0 at pe.entry_point
}