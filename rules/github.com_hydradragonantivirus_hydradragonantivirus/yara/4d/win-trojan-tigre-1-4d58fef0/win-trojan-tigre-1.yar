rule Win_Trojan_Tigre_1
{
strings:
	$a0 = { 0e1f073efe865500eb05905654cd208db658008bfeb9b006b402cd173e8a963f003e8ab64000eb }


condition:
	$a0
}