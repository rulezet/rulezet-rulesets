rule Win_Trojan_Horse_9
{
strings:
	$a0 = { 0835e87e032e891e2c062e8c062e0653 }


condition:
	$a0
}