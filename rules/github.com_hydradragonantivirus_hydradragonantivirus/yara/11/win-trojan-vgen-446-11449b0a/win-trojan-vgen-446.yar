rule Win_Trojan_VGEN_446
{
strings:
	$a0 = { bb0f00b91b012e810700004343e2 }


condition:
	$a0
}