rule Win_Trojan_Lucifer_4
{
strings:
	$a0 = { 01030055df00000000ffff01030000e1020000020000000103 }


condition:
	$a0
}