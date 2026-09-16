rule Win_Trojan_Guppy_2
{
strings:
	$a0 = { 8c84970089f283c21fb425cd21fec6 }


condition:
	$a0
}