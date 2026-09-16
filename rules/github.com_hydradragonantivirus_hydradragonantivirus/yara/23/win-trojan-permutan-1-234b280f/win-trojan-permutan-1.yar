rule Win_Trojan_Permutan_1
{
strings:
	$a0 = { cd212e8b9c09008bd6b92002b440cd217305585a59eb }


condition:
	$a0
}