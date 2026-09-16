rule Win_Trojan_Yeke_3
{
strings:
	$a0 = { 8cdae800005d81ed5e09bf1b0003fd8bf7b93b091f07fcac34 }


condition:
	$a0
}