rule Win_Trojan_Trojan_224
{
strings:
	$a0 = { a5c686c50401b41a8d969a04cd21b447b2008db6 }


condition:
	$a0
}