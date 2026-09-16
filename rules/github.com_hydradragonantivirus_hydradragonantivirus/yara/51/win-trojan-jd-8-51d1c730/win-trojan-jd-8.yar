rule Win_Trojan_JD_8
{
strings:
	$a0 = { 8801b440cd2133c9b8004299cd21b440b104ba8602cd21 }


condition:
	$a0
}