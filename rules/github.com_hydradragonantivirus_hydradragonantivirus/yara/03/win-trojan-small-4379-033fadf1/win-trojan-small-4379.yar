rule Win_Trojan_Small_4379
{
strings:
	$a0 = { 606a026a01e8??000000536a }


condition:
	$a0
}