rule Win_Trojan_Marzia_6
{
strings:
	$a0 = { 501e0633c08ed8813e120200f27403eb70900706268b0e2c008ec10e5afc33ffb001f2ae47b95757b83030cd21 }


condition:
	$a0
}