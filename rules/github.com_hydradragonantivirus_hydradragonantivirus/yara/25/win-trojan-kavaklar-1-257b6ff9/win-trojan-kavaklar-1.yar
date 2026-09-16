rule Win_Trojan_Kavaklar_1
{
strings:
	$a0 = { 5e83ee03565606ba9f8d33c08ec026ff361c002689161c002639161c0075c8268f061c0007 }


condition:
	$a0
}