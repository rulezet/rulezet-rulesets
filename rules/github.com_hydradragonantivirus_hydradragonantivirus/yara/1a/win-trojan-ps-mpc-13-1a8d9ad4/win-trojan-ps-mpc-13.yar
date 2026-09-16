rule Win_Trojan_PS_MPC_13
{
strings:
	$a0 = { 025cb82435cd21899ece028c86d002b4258d96c202 }


condition:
	$a0
}