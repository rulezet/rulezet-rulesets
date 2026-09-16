rule Win_Trojan_Burger_14
{
strings:
	$a0 = { 90b8000026a23d0226a23f0226a27f0250b419cd2126a23d02b4470401 }


condition:
	$a0
}