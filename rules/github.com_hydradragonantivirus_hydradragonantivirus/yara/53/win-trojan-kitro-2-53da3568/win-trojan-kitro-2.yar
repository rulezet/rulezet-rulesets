rule Win_Trojan_Kitro_2
{
strings:
	$a0 = { 4b494c54524f202a204d534e5748 }


condition:
	$a0
}