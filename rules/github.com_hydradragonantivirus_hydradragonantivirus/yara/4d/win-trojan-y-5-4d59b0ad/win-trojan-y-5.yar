rule Win_Trojan_Y_5
{
strings:
	$a0 = { b99e0bf32ea4061f53b82135cd218c }


condition:
	$a0
}