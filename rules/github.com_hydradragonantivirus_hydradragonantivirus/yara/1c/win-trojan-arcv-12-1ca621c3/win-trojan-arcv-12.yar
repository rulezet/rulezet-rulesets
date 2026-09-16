rule Win_Trojan_ARCV_12
{
strings:
	$a0 = { 1201bf1aff8134000046464775f7 }


condition:
	$a0
}