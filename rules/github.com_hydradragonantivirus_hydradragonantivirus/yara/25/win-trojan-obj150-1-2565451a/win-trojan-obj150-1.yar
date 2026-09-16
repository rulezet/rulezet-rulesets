rule Win_Trojan_OBJ150_1
{
strings:
	$a0 = { 0352e81e0072e581fa00015a750db1962bd152b440ba9601cd215aebc62a2e6f626a00b43fb103 }


condition:
	$a0
}