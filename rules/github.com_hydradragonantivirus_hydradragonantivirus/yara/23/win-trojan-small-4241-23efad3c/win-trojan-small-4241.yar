rule Win_Trojan_Small_4241
{
strings:
	$a0 = { 29c98d9923856200 }


condition:
	$a0
}