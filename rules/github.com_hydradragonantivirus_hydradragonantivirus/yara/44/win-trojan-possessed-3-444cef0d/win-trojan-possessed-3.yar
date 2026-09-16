rule Win_Trojan_Possessed_3
{
strings:
	$a0 = { 8c065101c7064f010408062eff2e4f01 }


condition:
	$a0
}