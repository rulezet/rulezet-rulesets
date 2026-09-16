rule Win_Trojan_Haze_3
{
strings:
	$a0 = { 2d6be2e6a2c0a28fab16e4b00580daa5ca745334954399d82931b5e370ac0b91f99ab5a6fab1fbb7 }


condition:
	$a0
}