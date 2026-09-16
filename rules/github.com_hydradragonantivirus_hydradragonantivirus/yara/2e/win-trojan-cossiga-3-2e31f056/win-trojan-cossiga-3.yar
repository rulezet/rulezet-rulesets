rule Win_Trojan_Cossiga_3
{
strings:
	$a0 = { 7003b41aba7003cd21b447b200be3204cd21c7452c5c00 }


condition:
	$a0
}