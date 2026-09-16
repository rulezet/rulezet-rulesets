rule Win_Trojan_Error_1
{
strings:
	$a0 = { eecd2180fcdd7426b82135cd212e891e14002e8c061600 }


condition:
	$a0
}