rule Win_Trojan_GR_4
{
strings:
	$a0 = { bb6303b9bc56b92936fd26298c }


condition:
	$a0
}