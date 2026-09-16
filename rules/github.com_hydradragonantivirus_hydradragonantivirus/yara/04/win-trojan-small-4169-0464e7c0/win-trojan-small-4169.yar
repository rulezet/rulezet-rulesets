rule Win_Trojan_Small_4169
{
strings:
	$a0 = { e80000000081ea09ae83635a81c27b07 }


condition:
	$a0
}