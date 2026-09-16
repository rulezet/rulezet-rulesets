rule Win_Trojan_Minimal_6
{
strings:
	$a0 = { 3dba9e00cd2193b44089f28bcecd21c3 }


condition:
	$a0
}