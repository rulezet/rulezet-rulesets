rule Win_Trojan_PS_3
{
strings:
	$a0 = { e90000e800005d81ed06018db6????bf0001a5a48d96????b41acd218d96????b90700b44ecd21eb }


condition:
	$a0
}