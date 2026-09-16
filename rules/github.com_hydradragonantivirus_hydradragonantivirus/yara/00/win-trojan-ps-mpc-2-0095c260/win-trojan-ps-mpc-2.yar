rule Win_Trojan_PS_MPC_2
{
strings:
	$a0 = { bfe101b97e032e812d51304747e2f7 }


condition:
	$a0
}