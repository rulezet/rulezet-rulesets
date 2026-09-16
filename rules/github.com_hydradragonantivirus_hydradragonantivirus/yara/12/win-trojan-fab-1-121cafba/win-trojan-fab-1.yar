rule Win_Trojan_Fab_1
{
strings:
	$a0 = { ba80ff30da8e1eae02e86aff73b7a701fc34ed48bb0001e85cf28e01c430bfc0db3d7b2ec54ef1 }


condition:
	$a0
}