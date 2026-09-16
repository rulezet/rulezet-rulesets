rule Win_Trojan_Zorm_17
{
strings:
	$a0 = { b8dd4bcd213d4bdd74[0-100]b82135cd21[0-100]b82125cd21 }


condition:
	$a0
}