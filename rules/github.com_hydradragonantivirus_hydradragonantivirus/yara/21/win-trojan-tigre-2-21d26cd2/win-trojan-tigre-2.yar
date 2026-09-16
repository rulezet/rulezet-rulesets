rule Win_Trojan_Tigre_2
{
strings:
	$a0 = { 06b402cd170e0e1f073efe864e008db651008bfeb9b706b402cd173e8a9638003e8ab63900 }


condition:
	$a0
}