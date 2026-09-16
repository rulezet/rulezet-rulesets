rule Win_Trojan_Gen_252
{
strings:
	$a0 = { 560c8b4e0a1e558b460e8effff5e088b5e06cd255a5d1fbb01007205bbff3f000031c0881e06 }


condition:
	$a0
}