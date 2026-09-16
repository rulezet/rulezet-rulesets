rule Win_Trojan_Fortlink_1
{
strings:
	$a0 = { 313233343536372e6c6e6b }

	$a1 = { 47415a544f4e4941[0-36]5c4652554e4c4f472e545854 }


condition:
	$a0 and $a1
}