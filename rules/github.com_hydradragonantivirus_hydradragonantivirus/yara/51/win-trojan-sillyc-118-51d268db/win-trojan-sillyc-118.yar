rule Win_Trojan_SillyC_118
{
strings:
	$a0 = { d3e8a3130158250f00b910002bc85803c150b440cd21582d0300a3ed01ba1001b9f4012bcab4 }


condition:
	$a0
}