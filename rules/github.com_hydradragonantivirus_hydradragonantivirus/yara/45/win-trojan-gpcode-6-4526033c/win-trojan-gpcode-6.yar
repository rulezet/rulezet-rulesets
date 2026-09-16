rule Win_Trojan_Gpcode_6
{
strings:
	$a0 = { 5c52756e[0-3]633a5c746d705c6465636f64655c }

	$a1 = { 746d702e626174 }


condition:
	$a0 and $a1
}