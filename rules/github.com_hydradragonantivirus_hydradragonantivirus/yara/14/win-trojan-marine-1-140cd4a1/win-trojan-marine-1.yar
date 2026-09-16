rule Win_Trojan_Marine_1
{
strings:
	$a0 = { 020000002ec6061201fdeb00be48148bfec3b44db280cd13b91e13b4 }


condition:
	$a0
}