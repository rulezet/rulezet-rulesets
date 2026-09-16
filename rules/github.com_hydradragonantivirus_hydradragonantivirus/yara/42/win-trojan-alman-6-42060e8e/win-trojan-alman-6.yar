rule Win_Trojan_Alman_6
{
strings:
	$a0 = { 33c085c0740fcc[0-255]5bb99e040000800419??e2faeb06e8edffffffc3 }


condition:
	$a0
}