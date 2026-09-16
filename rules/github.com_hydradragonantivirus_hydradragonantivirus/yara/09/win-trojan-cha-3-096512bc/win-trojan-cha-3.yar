rule Win_Trojan_Cha_3
{
strings:
	$a0 = { ff7504b83412cf505351525557561e062e803e4a06 }


condition:
	$a0
}