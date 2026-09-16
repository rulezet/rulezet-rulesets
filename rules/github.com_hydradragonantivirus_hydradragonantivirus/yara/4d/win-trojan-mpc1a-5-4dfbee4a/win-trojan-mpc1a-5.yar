rule Win_Trojan_MPC1a_5
{
strings:
	$a0 = { a5c686920809b41a8d966708cd21b447b2008db6 }


condition:
	$a0
}