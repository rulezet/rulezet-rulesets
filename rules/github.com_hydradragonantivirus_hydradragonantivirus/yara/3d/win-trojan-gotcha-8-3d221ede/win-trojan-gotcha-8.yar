rule Win_Trojan_Gotcha_8
{
strings:
	$a0 = { b96f03f3a4ba4101061fb82125cd2107 }


condition:
	$a0
}