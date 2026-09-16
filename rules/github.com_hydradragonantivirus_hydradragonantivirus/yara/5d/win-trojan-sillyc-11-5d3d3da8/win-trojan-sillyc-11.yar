rule Win_Trojan_SillyC_11
{
strings:
	$a0 = { 57e81000c30000b280b41acd21c32a2e434f4d005ea4a5568d545ae8ebffb44e8d5407cd2172e6d06c74b44f72 }


condition:
	$a0
}