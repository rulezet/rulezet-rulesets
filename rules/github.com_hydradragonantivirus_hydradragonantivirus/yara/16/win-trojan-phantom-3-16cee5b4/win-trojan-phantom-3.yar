rule Win_Trojan_Phantom_3
{
strings:
	$a0 = { 8bfa1e07b000b95000fcf2ae83ef04 }


condition:
	$a0
}