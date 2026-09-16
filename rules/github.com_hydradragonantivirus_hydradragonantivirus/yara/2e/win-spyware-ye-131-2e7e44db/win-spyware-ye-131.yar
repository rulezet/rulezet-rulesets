rule Win_Spyware_ye_131
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]804e8a5f9b3a6d1f416e11fb9b3868 }


condition:
	$a0
}