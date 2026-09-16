rule Win_Trojan_Hackin_1
{
strings:
	$a0 = { 40b9008cba0000cd21b8013dbabb05cd2193b440b9008cba0000cd21b8013dbad805cd2193b440 }


condition:
	$a0
}