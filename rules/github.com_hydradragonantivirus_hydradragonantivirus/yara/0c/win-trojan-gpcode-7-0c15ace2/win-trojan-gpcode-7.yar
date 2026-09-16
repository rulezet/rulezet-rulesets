rule Win_Trojan_Gpcode_7
{
strings:
	$a0 = { 5c52756e[0-3]726d72006774640066727800 }

	$a1 = { 633a5c746d705c6465636f64655c }


condition:
	$a0 and $a1
}