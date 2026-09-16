rule Win_Trojan_Dilo_2
{
strings:
	$a0 = { b82135cd21061fb866258bd3cd211f880e????b021bae600cd21 }


condition:
	$a0
}