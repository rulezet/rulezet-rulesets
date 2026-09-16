rule Win_Trojan_Small_4466
{
strings:
	$a0 = { 6a00e872feffffc3558d6c248c81ec140100008d45e050 }


condition:
	$a0
}