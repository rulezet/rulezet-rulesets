rule Win_Trojan_Hd_2
{
strings:
	$a0 = { 81382e6e657774ab81382e746c7374a3 }

	$a1 = { 3007 }


condition:
	$a0 and $a1
}