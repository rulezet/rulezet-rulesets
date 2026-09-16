rule Win_Trojan_Trojan_179
{
strings:
	$a0 = { ba9e00cd2193b44083c262b11fcd21c3 }


condition:
	$a0
}