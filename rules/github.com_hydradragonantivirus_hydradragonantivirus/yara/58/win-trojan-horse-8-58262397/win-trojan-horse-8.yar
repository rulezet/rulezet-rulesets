rule Win_Trojan_Horse_8
{
strings:
	$a0 = { 0835e87e032e891ef4062e8c06f60653 }


condition:
	$a0
}