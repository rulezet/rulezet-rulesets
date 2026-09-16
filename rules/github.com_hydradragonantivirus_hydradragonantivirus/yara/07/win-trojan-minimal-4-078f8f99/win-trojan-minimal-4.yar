rule Win_Trojan_Minimal_4
{
strings:
	$a0 = { 9e00cd2193b4408bd68bcecd21c3 }


condition:
	$a0
}