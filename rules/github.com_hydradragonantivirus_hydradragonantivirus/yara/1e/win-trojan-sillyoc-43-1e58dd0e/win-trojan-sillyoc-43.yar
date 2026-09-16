rule Win_Trojan_SillyOC_43
{
strings:
	$a0 = { ba2f01b90200b44ecd21e90700b44fba2f01cd21b8023dba9e00cd2193b94d00b440ba0001cd21b4 }


condition:
	$a0
}