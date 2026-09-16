rule Win_Trojan_Gpcode_4
{
strings:
	$a0 = { 5c52756e[0-3]633a5c746d705c6465636f64655c }

	$a1 = { 5c4d696e69 }

	$a2 = { 2e657865 }


condition:
	$a0 and $a1 and $a2
}