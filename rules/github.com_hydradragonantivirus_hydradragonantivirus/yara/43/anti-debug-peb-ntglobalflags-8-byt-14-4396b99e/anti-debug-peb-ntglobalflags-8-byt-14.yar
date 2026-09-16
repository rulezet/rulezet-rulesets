rule anti_debug__PEB_NtGlobalFlags__8_byt_14_
{
strings:
	$a0 = { 64a1300000008b406883e07085c0 }

condition:
	$a0
}