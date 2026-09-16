rule Win_Trojan_Small_4257
{
strings:
	$a0 = { 60e8??000000[0-220]78633244 }


condition:
	$a0
}