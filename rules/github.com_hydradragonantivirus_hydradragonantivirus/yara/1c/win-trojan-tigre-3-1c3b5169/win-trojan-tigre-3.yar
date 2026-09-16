rule Win_Trojan_Tigre_3
{
strings:
	$a0 = { 0e1f073efe864c008db64f008bfeb9b406b402cd173e8a9637003e8ab63800eb06b44ccd21 }


condition:
	$a0
}