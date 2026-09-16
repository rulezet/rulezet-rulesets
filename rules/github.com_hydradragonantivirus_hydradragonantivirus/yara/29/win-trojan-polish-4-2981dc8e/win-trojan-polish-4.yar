rule Win_Trojan_Polish_4
{
strings:
	$a0 = { 3dcd218bd8b440ba0001b12dcd21 }


condition:
	$a0
}