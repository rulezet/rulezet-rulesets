rule Win_Trojan_VanKill_1
{
strings:
	$a0 = { 746f6e20416e7469566972757320746f20437261736820210a0a002d4c494247 }


condition:
	$a0
}