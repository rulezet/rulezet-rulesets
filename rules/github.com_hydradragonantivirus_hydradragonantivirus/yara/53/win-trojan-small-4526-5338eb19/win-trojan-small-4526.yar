rule Win_Trojan_Small_4526
{
strings:
	$a0 = { bd????4200ba????42008b1affd301d5e83600000050e82000000055e8 }


condition:
	$a0
}