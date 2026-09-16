rule Win_Trojan_Tazman_1
{
strings:
	$a0 = { b9c202ba0000cd210e1fb80242e84b00b90002f7f1408916a602a3a802b80042e83800b91a00 }


condition:
	$a0
}