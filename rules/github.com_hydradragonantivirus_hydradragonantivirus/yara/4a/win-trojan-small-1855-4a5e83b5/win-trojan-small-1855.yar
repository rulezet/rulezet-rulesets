rule Win_Trojan_Small_1855
{
strings:
	$a0 = { 6a00516a016a026a2068ff010f0068d0704000686870400055a4ff1510604000 }


condition:
	$a0
}