rule Win_Trojan_Peed_25
{
strings:
	$a0 = { b91332230f83c00101c3e2f985db74f5b9ed }


condition:
	$a0
}