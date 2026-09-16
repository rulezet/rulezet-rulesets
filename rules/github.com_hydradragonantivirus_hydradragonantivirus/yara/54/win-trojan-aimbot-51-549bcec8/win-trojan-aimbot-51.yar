rule Win_Trojan_Aimbot_51
{
strings:
	$a0 = { e81e160000e940feffff558bec81ec28030000a3d8ad4000890dd4ad40008915 }


condition:
	$a0
}