rule Win_Trojan_Trojan_238
{
strings:
	$a0 = { be10002e812c2d2346464b75f6 }


condition:
	$a0
}