rule Win_Trojan_Rave_1
{
strings:
	$a0 = { b8023dcc93b80057cc5152b43fba??????????cc803e }


condition:
	$a0
}