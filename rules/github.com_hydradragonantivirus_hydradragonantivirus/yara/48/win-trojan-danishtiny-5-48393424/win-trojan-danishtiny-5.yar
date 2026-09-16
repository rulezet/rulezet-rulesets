rule Win_Trojan_DanishTiny_5
{
strings:
	$a0 = { abe2fa5e595b58c3e8dbff89843f02b4408d940501 }


condition:
	$a0
}