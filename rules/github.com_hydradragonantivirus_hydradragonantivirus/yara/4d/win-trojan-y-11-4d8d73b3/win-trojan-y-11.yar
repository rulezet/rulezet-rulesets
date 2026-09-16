rule Win_Trojan_Y_11
{
strings:
	$a0 = { 03fcb85a5acd213d4f4775450e1f8db63b00b462cd218cc83bd8538ec3741e83c310015c02015c041f2e8b6406 }


condition:
	$a0
}