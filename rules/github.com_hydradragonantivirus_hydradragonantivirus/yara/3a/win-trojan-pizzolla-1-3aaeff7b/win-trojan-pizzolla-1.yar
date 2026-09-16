rule Win_Trojan_Pizzolla_1
{
strings:
	$a0 = { 1fb94000b02ef2aeb90300be1104f3a67406e96d01e95d }


condition:
	$a0
}