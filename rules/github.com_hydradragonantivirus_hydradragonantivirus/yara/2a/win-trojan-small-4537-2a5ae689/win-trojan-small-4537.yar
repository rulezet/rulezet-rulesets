rule Win_Trojan_Small_4537
{
strings:
	$a0 = { bff6fa5a12e34b7f83efaff2cbdba2ff }


condition:
	$a0
}