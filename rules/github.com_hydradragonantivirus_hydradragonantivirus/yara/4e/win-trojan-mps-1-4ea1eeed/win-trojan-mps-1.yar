rule Win_Trojan_MPS_1
{
strings:
	$a0 = { 841802b90400ba160203d6b440cd21 }


condition:
	$a0
}