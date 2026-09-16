rule Win_Trojan_Cyberwarrior_4
{
strings:
	$a0 = { e800005d81ed1e011e06bf00018db63002b90500f3a4b41a8d969b04cd21b44e8d963a02b107cd21 }


condition:
	$a0
}