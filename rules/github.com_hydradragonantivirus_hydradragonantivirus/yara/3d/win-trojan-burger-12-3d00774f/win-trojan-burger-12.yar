rule Win_Trojan_Burger_12
{
strings:
	$a0 = { eb002ec70641020000b419cd212ea27102b447b200be7302cd21f8731fb417ba4b02cd213cff7514b42ccd212ea071028bdab90200b600cd26e9f300b43bba6f }


condition:
	$a0
}