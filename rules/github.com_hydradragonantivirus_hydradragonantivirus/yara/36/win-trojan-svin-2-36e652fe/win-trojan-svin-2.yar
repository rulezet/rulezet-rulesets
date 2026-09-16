rule Win_Trojan_Svin_2
{
strings:
	$a0 = { 33c08ed08ec0bb00808be353b90300ba0001b80102cd137201c3cd1900 }


condition:
	$a0
}