rule Win_Trojan_GR_3
{
strings:
	$a0 = { bb6303b92a7cbd529e482681ac }


condition:
	$a0
}