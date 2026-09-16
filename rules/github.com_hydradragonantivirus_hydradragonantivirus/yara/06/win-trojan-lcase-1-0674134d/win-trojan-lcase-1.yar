rule Win_Trojan_Lcase_1
{
strings:
	$a0 = { 03e8beffb001e8b9ffe8bbffc3b912 }


condition:
	$a0
}