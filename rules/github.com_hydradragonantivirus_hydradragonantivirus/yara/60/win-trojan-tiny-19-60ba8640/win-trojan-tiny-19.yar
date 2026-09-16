rule Win_Trojan_Tiny_19
{
strings:
	$a0 = { 010e59f3a4ba4601b44ecd217301cbb8023dba9e00cd2193b43fba4c015459cd21054c005033 }


condition:
	$a0
}