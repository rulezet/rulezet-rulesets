rule Win_Trojan_Vandor_2
{
strings:
	$a0 = { b0e3be????b9f303d00c46e2fb }


condition:
	$a0
}