rule Win_Trojan_Piggy_1
{
strings:
	$a0 = { 408d960601b9c502cd21e899fdc3b402e8c0ffb404e8bbffb401e8b6ffb400e8b1ffb401e8acff }


condition:
	$a0
}