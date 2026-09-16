rule Win_Trojan_Proto_1
{
strings:
	$a0 = { e8e3ffb440b90100ba6903e8e6ffb440b90200ba7203e8dbffb440b90200ba7803e8d0ffc3 }


condition:
	$a0
}