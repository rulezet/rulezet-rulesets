rule Win_Trojan_Haha_2
{
strings:
	$a0 = { 636f7079202530202577696e646972255c2568616861252e626174 }


condition:
	$a0
}