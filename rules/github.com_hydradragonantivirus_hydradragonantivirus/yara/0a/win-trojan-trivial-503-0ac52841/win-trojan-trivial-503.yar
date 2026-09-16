rule Win_Trojan_Trivial_503
{
strings:
	$a0 = { 4a01b90200b44ecd21b44fba4a01cd2133c9b80143cd21b8023dba9e00cd2193b80057cd215251b95600b440ba0001 }


condition:
	$a0
}