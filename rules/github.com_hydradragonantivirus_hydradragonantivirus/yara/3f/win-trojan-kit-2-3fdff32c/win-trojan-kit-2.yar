rule Win_Trojan_Kit_2
{
strings:
	$a0 = { 9a04b82125cd21b81c35cd21891e1500 }


condition:
	$a0
}