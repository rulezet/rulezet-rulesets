rule Win_Trojan_Leo_4
{
strings:
	$a0 = { b94d01baedff03d7cd21b409b92e00bee60003f7e816 }


condition:
	$a0
}