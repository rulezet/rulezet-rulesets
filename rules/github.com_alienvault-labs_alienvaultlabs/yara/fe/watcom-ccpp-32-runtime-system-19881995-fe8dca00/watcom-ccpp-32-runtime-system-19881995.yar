rule _WATCOM_CCpp_32_RunTime_System_19881995_
{
	meta:
		description = "WATCOM C/C++ 32 Run-Time System 1988-1995"
	strings:
		$0 = {FB 83 89 E3 89 89 66 66 BB 29 C0 B4 30 CD}
	condition:
		$0 at entrypoint
}