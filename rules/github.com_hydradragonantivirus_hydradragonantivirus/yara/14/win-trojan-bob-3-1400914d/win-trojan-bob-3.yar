rule Win_Trojan_Bob_3
{
strings:
	$a0 = { 07720680fe01750145b200be0000161fb447cd210e }


condition:
	$a0
}