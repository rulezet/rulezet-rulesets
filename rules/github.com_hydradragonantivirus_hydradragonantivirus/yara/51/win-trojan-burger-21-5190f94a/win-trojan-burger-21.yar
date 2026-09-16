rule Win_Trojan_Burger_21
{
strings:
	$a0 = { 90b8000026a2410226a2430226a2830250b419cd2126a24102b4470401 }


condition:
	$a0
}