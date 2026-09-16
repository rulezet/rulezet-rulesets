rule Win_Trojan_Beda_4
{
strings:
	$a0 = { f3a4b8dabecd213dfec07503eb5e90b452cd21268b }


condition:
	$a0
}