rule Win_Trojan_Gpcode_5
{
strings:
	$a0 = { 5c52756e[0-3]633a5c746d705c6465636f64655c }

	$a1 = { 6f70656e[0-72]746d702e626174 }


condition:
	$a0 and $a1
}