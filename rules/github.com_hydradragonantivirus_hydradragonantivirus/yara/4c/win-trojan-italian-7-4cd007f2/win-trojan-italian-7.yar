rule Win_Trojan_Italian_7
{
strings:
	$a0 = { 01b964062e8a272e32a690072e882743e2f2c3 }


condition:
	$a0
}