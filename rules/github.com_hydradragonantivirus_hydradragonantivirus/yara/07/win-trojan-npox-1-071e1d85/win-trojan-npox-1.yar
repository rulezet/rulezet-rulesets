rule Win_Trojan_Npox_1
{
strings:
	$a0 = { 012ea3bc01b440b97401ba0001cd217212b8004233c933d2cd21b440b103babb01cd21 }


condition:
	$a0
}