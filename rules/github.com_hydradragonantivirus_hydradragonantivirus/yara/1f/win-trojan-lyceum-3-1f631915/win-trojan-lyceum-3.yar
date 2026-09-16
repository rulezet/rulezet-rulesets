rule Win_Trojan_Lyceum_3
{
strings:
	$a0 = { 83ee03fc5053b8cdabcd213dffff7502eb3c1e068cc0488ec0bb030026832f2e4b8b072d2e0089078ec00e1f5633ff }


condition:
	$a0
}