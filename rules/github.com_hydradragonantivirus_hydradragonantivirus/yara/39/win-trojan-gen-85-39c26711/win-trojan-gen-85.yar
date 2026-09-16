rule Win_Trojan_Gen_85
{
strings:
	$a0 = { b4178d165502cd21b43b8d167902cd21 }


condition:
	$a0
}