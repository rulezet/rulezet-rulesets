rule Win_Trojan_Silly_97
{
strings:
	$a0 = { 636f7079202530202577696e646972255c6465736b746f705c2a2e626174 }


condition:
	$a0
}