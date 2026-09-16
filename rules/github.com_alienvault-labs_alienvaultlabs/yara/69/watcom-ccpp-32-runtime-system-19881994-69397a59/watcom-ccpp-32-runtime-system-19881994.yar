rule _WATCOM_CCpp_32_RunTime_System_19881994_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1994"
	strings:
		$0 = {E9 57}
	condition:
		$0 at entrypoint
}