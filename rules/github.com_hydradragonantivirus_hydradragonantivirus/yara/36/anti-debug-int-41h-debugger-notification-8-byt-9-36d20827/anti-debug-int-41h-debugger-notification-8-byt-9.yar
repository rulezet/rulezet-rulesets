rule anti_debug__INT_41h_Debugger_Notification__8_byt_9_
{
strings:
	$a0 = { 576a4f682a002a00e8 }

condition:
	$a0
}