rule Win_Trojan_Sectho_14
{
strings:
	$a0 = { 65137374630f57fb6367c90e1d0097326e642d746865bffc636d67be9c2f696e7374616c7068703f73bfbd15f872633d }


condition:
	$a0
}