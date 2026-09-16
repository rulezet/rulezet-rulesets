rule Win_Trojan_Saturday_1
{
strings:
	$a0 = { 9d02a4e2fd06b82135cd211f891e5302 }


condition:
	$a0
}