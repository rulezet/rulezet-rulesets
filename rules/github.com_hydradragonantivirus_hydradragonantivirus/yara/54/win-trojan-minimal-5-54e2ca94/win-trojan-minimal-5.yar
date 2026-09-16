rule Win_Trojan_Minimal_5
{
strings:
	$a0 = { b44eba1a01cd21b8013dba9e00cd2193b4408bd68bcecd21c32a2e2a00 }


condition:
	$a0
}