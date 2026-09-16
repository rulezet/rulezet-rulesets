rule Win_Trojan_Lava_2
{
strings:
	$a0 = { 4c41454d21686dc81741a6c81c59c7a2b908b6d80e0418ffea0c04c805a7468cde684341728a45d8f84ecf241105aba03415fbdd73b0606fe607353c }


condition:
	$a0
}