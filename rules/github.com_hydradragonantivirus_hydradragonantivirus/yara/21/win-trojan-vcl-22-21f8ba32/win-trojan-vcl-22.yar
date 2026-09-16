rule Win_Trojan_VCL_22
{
strings:
	$a0 = { 87dd33dde85d01e81400e878010bc07503e86a01b8004ccd2156e28ace58558bec83ec40b44732d28d76c0cd21b43bba4201cd21e80d00b43b8d56c0cd218be5 }


condition:
	$a0
}