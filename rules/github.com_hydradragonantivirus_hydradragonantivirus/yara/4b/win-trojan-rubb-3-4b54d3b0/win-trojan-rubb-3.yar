rule Win_Trojan_Rubb_3
{
strings:
	$a0 = { e80000fc0e1f8bec836e00035ebb2400b9????2bcb803064fe0843e2f8b8 }


condition:
	$a0
}