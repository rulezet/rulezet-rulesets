rule Win_Trojan_MPC1a_6
{
strings:
	$a0 = { a5a5c6869c0402b41a8d967104cd21b447b2008db6 }


condition:
	$a0
}