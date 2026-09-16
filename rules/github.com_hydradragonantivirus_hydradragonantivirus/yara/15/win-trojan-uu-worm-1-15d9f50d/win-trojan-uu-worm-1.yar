rule Win_Trojan_UU_Worm_1
{
strings:
	$a0 = { 807c023a75e9be0001e81a00b8024233c933d2cd21b4408b0e9602ba9f02cd21b43ecd2161c3 }


condition:
	$a0
}