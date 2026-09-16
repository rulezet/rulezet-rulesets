rule Win_Trojan_PS_MPC_6
{
strings:
	$a0 = { 96b6028d960301b440b94601cd2133c9b8004233d2cd21 }


condition:
	$a0
}