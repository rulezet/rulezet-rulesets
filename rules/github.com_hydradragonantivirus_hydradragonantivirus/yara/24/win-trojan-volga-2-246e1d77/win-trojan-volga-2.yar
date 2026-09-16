rule Win_Trojan_Volga_2
{
strings:
	$a0 = { be007c33fffa8ed78be6fbea3a00c007 }


condition:
	$a0
}