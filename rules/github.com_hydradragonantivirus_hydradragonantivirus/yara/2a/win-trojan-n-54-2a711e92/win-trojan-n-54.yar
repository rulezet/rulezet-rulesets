rule Win_Trojan_N_54
{
strings:
	$a0 = { d0bc007c8ec4fb8bd8cd13b90b00b80702cd137302cd18ea4900007c }


condition:
	$a0
}