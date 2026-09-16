rule Win_Trojan_Small_4474
{
strings:
	$a0 = { ff74241c588d80??647704506862343504e856000000404050 }


condition:
	$a0
}