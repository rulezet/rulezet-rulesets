rule Win_Trojan_Trojan_295
{
strings:
	$a0 = { b80200b90005fa99cd26fbcd20 }


condition:
	$a0
}