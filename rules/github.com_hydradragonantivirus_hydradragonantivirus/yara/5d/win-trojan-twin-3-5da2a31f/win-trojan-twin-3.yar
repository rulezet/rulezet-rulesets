rule Win_Trojan_Twin_3
{
strings:
	$a0 = { ffcd213c077507e82500b44ccd21 }


condition:
	$a0
}