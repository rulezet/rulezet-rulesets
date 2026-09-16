rule Win_Trojan_Nullset_1
{
strings:
	$a0 = { 01b9ce02be0e098bd92800e2fa }


condition:
	$a0
}