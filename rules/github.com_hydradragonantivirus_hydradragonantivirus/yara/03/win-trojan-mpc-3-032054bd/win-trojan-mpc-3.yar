rule Win_Trojan_MPC_3
{
strings:
	$a0 = { 028d960301b93a01b440cd2133c9b8004299cd21b903008d96aa02b440cd21 }


condition:
	$a0
}