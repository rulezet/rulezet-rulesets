rule Win_Trojan_CrazyImp_3
{
strings:
	$a0 = { cd2f33c08ed8832e1304048cc88ed8488ec026812e03 }


condition:
	$a0
}