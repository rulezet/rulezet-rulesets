rule Win_Trojan_VB_1003
{
strings:
	$a0 = { 833d4c9e4f00007505e901000000c3e846000000e873 }

	$a1 = { 4e454f78 }


condition:
	$a0 and $a1
}