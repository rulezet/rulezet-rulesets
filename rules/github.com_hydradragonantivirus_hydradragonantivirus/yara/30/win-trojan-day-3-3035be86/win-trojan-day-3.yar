rule Win_Trojan_Day_3
{
strings:
	$a0 = { 062c00b90010fc33ffb050f2ae7518 }


condition:
	$a0
}