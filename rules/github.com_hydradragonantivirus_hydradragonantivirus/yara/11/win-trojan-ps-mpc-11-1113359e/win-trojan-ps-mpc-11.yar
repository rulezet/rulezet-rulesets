rule Win_Trojan_PS_MPC_11
{
strings:
	$a0 = { bf19002e812d36324747e2f7 }


condition:
	$a0
}