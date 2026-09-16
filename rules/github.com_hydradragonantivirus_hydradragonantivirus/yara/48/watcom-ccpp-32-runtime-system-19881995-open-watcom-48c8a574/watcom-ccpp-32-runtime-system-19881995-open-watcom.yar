import "pe"
rule _WATCOM_CCpp_32_RunTime_System_19881995__Open_Watcom_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1995 -> Open Watcom"
	strings:
		$0 = {E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54}
	condition:
		$0 at pe.entry_point
}