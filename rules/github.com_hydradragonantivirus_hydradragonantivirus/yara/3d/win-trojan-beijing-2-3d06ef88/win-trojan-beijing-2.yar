rule Win_Trojan_Beijing_2
{
strings:
	$a0 = { 02720d80fc04730880fa807303e8 }


condition:
	$a0
}