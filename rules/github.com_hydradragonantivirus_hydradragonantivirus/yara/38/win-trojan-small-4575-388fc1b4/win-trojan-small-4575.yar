rule Win_Trojan_Small_4575
{
strings:
	$a0 = { d9ee83ec1cd934248b44240c83c41cbf621940008a179090 }


condition:
	$a0
}