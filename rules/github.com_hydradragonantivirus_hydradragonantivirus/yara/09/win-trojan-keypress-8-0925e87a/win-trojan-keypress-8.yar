rule Win_Trojan_Keypress_8
{
strings:
	$a0 = { 25cd2107bb2a05b104d3eb83c3112e }


condition:
	$a0
}