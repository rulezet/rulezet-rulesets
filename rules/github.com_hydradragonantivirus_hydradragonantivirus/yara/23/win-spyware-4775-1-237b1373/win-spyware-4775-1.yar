rule Win_Spyware_4775_1
{
strings:
	$a0 = { 6081c3eaf7ddd381c31608222c81c312 }


condition:
	$a0
}