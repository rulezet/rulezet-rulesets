rule Win_Trojan_BOO_2
{
strings:
	$a0 = { 8ec0b80102bb0008b90000b600cd13ea700800 }


condition:
	$a0
}