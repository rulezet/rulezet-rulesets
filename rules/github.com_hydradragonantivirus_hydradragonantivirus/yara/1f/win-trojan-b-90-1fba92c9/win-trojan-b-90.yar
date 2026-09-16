rule Win_Trojan_B_90
{
strings:
	$a0 = { 7da5a5a113048bd0b106d3e0be007cbf00048ec0b90b00f3a674072d4000ff0e1304fac7064c }


condition:
	$a0
}