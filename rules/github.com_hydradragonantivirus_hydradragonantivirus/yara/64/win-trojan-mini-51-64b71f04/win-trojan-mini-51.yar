rule Win_Trojan_Mini_51
{
strings:
	$a0 = { b92d00b440cd21b43ecd21b44febdfc3 }


condition:
	$a0
}