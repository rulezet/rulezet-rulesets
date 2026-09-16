rule Win_Trojan_Chameleon_1
{
strings:
	$a0 = { 0d33d9902bda2bd833d12bd9310547464b9043f84240e2e7 }


condition:
	$a0
}