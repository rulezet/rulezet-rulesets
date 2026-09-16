rule Win_Trojan_Jara_1
{
strings:
	$a0 = { 900e1f0e0790b41a8bd681c20003cd2190b44eb937008bd683c225eb08902a2e434f4d000090cd21eb439090 }


condition:
	$a0
}