rule Win_Trojan_Dilavtor_1
{
strings:
	$a0 = { 25733f693d257326753d2573266c3d257326663d256426613d2573 }


condition:
	$a0
}