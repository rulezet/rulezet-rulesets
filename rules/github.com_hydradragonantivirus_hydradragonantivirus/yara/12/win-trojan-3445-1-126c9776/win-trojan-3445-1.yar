rule Win_Trojan_3445_1
{
strings:
	$a0 = { e91f8cc833d2bb1000f7e303c183d2 }


condition:
	$a0
}