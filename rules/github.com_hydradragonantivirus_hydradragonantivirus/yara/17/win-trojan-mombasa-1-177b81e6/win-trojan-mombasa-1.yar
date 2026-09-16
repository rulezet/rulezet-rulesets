rule Win_Trojan_Mombasa_1
{
strings:
	$a0 = { 0800b1d9b1f78b887e4f5e8b80504f83c64b9fb8834f8bb8614f8a3cb1edb1fc46bfa04f8a1c9f9f28fb8bb8614fb1 }


condition:
	$a0
}