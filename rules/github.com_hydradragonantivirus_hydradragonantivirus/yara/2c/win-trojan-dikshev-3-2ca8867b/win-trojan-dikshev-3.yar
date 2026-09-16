rule Win_Trojan_Dikshev_3
{
strings:
	$a0 = { cc33c2cd01e2f98bdd81c3bf000e33c08ec0fa2689 }


condition:
	$a0
}