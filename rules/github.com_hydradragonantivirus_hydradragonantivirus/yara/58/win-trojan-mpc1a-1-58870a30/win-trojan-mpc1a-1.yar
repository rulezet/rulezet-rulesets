rule Win_Trojan_MPC1a_1
{
strings:
	$a0 = { bed201a5a4c644fde98944fe050301505133c9e88d00b002e87e00b4408d964e0859cd21b80242 }


condition:
	$a0
}