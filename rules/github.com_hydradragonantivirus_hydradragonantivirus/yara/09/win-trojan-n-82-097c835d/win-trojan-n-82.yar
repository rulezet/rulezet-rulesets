rule Win_Trojan_N_82
{
strings:
	$a0 = { bcd5fcffebeb5f5e5b59595dc3000000ffffffff010000005c000000ffffffff0a00000064636366756b2e6d73670000ffffffff77000000524152 }


condition:
	$a0
}