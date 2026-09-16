rule Win_Trojan_Hellfire_9
{
strings:
	$a0 = { 8bfeb90f02adeb04abe2fac335????73f7 }


condition:
	$a0
}