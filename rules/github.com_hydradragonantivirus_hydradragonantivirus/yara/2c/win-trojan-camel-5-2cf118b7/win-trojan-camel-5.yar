rule Win_Trojan_Camel_5
{
strings:
	$a0 = { cd210ae475001e06b44abbffffcd2181eb2100b8004acd21b80048bb2000cd218ec0488e }


condition:
	$a0
}