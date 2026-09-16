rule Win_Trojan_PS_MPC_7
{
strings:
	$a0 = { a5b41a8d965d02cd218d969401b44eb90700cd2172 }


condition:
	$a0
}