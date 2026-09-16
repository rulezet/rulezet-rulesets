rule Win_Trojan_Small_4407
{
strings:
	$a0 = { 0d??2e42005050682c6a35f3e8 }


condition:
	$a0
}