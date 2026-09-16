rule Win_Trojan_F_26
{
strings:
	$a0 = { 3e8986ac01b440b9c6008d960301cd21b8004233c933d2cd21b440b903008d96ab01cd21b4 }


condition:
	$a0
}