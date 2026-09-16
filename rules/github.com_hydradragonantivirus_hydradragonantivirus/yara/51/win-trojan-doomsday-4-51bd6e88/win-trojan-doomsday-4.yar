rule Win_Trojan_Doomsday_4
{
strings:
	$a0 = { 01b9ce02bef6048bd92800e2fa }


condition:
	$a0
}