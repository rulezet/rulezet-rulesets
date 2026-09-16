rule Win_Trojan_AP_2
{
strings:
	$a0 = { c08ed8cd1248a31304c1e0068ec0fcb9000133ffbe007cf3a5be4c00bf9400a5a54e4ec744fe84 }


condition:
	$a0
}