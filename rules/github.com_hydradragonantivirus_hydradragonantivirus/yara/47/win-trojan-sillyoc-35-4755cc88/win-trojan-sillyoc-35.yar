rule Win_Trojan_SillyOC_35
{
strings:
	$a0 = { cd215152ba9e00b8013dcd2193b440b98a02ba0001cd215a59b80157cd21b43ecd21b44fcd }


condition:
	$a0
}