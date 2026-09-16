rule Win_Trojan_Delf_417
{
strings:
	$a0 = { e856f5fbff33c9ba88e749008bc3e8acf5fbffff75f06804e849008d95d8fdffff8b45f0e8eab2f6ffffb5d8fdffff8d85dcfdffffba03000000e8e066f6ff }


condition:
	$a0
}