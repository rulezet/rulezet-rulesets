rule Win_Trojan_Cyberwarrior_3
{
strings:
	$a0 = { 2702b90500f3a4b41a8d964602cd21b44e8d963102b107cd217303e9d400b8014332c98d9664 }


condition:
	$a0
}