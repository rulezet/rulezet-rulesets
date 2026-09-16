rule Win_Trojan_V_33
{
strings:
	$a0 = { 8309be100c8a1cd0c3881c464a83fa0075f3b8100cffe0 }


condition:
	$a0
}