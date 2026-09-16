rule Win_Trojan_Moon_3
{
strings:
	$a0 = { 03c18bce33dbb3332bcb86ccbf420186e0abbf5201abbf6101abbf6701ab59b44dfec4cd21 }


condition:
	$a0
}