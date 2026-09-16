rule Win_Trojan_Popwin_51
{
strings:
	$a0 = { 387e61727b7d7160206e63662568646634363c3b352e }


condition:
	$a0
}