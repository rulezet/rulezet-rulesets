rule Win_Trojan_Hellfire_1
{
strings:
	$a0 = { 33c9bac001cd21723bb8003dba9e00cd2193b43fb90100ba1005cd21b43ecd21b44f803e1005b474d7b8023dba9e }


condition:
	$a0
}