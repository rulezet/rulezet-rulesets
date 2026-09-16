rule Win_Trojan_Hoppity_1
{
strings:
	$a0 = { 13047f31c08ed0bc007c8ed889e6b8c09f8ec031ffb94d01f3a4ea6100c09fb90200ba80003e813ebf7d0101 }


condition:
	$a0
}