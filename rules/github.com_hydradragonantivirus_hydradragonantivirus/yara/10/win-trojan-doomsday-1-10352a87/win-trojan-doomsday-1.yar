rule Win_Trojan_Doomsday_1
{
strings:
	$a0 = { a00301b9ce02be????8bd92800e2fa3ca854c9 }


condition:
	$a0
}