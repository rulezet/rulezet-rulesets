rule Win_Trojan_Small_4346
{
strings:
	$a0 = { 29c98d99235562008d9bddeeddff5353 }


condition:
	$a0
}