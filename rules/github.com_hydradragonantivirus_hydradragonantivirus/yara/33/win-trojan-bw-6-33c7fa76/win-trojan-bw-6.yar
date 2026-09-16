rule Win_Trojan_BW_6
{
strings:
	$a0 = { 0300cd2000bb1501b975012e810700004343e2f7 }


condition:
	$a0
}