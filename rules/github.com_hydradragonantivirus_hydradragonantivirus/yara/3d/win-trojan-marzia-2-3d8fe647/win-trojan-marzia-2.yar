rule Win_Trojan_Marzia_2
{
strings:
	$a0 = { d8813e120200f27402eb6f0706268b0e2c008ec10e5afc33ffb001f2ae47b95757b83030cd }


condition:
	$a0
}