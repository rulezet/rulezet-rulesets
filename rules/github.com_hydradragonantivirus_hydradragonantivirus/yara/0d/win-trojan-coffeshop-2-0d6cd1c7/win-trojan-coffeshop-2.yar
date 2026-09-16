rule Win_Trojan_Coffeshop_2
{
strings:
	$a0 = { 656553686f7020b003cf9c3dda337505b801a59dcf }


condition:
	$a0
}