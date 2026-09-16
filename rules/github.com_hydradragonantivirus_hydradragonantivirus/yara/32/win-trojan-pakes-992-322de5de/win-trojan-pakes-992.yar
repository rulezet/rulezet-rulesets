rule Win_Trojan_Pakes_992
{
strings:
	$a0 = { 606a006a00e80c0000006f6470647833322e646c }


condition:
	$a0
}