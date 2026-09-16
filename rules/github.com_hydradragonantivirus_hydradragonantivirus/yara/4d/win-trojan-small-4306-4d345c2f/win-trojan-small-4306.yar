rule Win_Trojan_Small_4306
{
strings:
	$a0 = { 81e889f226262d77c9d8d98d3405000000008d7433008db6ccedffff81eeccedffff }


condition:
	$a0
}