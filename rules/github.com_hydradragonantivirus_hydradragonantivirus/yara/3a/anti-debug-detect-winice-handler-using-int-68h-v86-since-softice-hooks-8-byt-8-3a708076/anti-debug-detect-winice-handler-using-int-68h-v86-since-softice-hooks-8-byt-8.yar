rule anti_debug__Detect_WinICE_handler_using_INT_68h__V86__since_SoftICE_hooks__8_byt_8_
{
strings:
	$a0 = { b443cd68663d86f3 }

condition:
	$a0
}