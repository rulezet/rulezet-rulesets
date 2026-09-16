rule Win_Trojan_N_34
{
strings:
	$a0 = { 8bfc368b2d81ed03012e803e3301b9742db91e048dbe3301ba0100 }


condition:
	$a0
}