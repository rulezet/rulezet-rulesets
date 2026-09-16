rule Win_Trojan_C_43
{
strings:
	$a0 = { 7c005a1fb41acd21bc3d03b44abb3700cd21e83500be5202e81400b8004bbb3c02ba5202cd }


condition:
	$a0
}