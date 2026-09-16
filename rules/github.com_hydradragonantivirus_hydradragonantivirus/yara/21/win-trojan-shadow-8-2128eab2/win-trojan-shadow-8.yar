rule Win_Trojan_Shadow_8
{
strings:
	$a0 = { b435cd21891c8c4402b425cd21c3 }


condition:
	$a0
}