rule Win_Trojan_Cossiga_1
{
strings:
	$a0 = { 012bd3b9730303cbb4408b5d57cd21 }


condition:
	$a0
}