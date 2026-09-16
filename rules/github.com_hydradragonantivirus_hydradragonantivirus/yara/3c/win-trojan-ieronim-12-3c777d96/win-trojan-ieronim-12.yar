rule Win_Trojan_Ieronim_12
{
strings:
	$a0 = { c08ec0b84b55263906dc01747326a3dc011e26c53e0400 }


condition:
	$a0
}