rule Win_Trojan_Small_4065
{
strings:
	$a0 = { e80b00000059535557e874000000eb6583c404eb5b }


condition:
	$a0
}