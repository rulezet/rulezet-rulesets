rule Win_Trojan_Volga_5
{
strings:
	$a0 = { be007c33fffa8ed78be6fbea3301c007 }


condition:
	$a0
}