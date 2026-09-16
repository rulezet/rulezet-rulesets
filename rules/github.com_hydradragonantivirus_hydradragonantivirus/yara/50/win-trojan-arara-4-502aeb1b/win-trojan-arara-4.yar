rule Win_Trojan_Arara_4
{
strings:
	$a0 = { 03e9c000b80043ba1efdcd2151b8014333c9cd21ccb8023dba1efdcd2193b80057cd215152b4 }


condition:
	$a0
}