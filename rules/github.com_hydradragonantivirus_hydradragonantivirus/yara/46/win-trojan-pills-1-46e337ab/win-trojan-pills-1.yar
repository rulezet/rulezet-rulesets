rule Win_Trojan_Pills_1
{
strings:
	$a0 = { fb0005338e3395cd66b4038dd16b45b940008a21fb0205338e3395cd66e80500ef40ca964001fe30 }


condition:
	$a0
}