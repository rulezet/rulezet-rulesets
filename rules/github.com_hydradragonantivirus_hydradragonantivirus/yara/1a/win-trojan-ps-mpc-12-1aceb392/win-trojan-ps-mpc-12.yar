rule Win_Trojan_PS_MPC_12
{
strings:
	$a0 = { 1c002e810502344747e2f7 }


condition:
	$a0
}