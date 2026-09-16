rule Win_Trojan_Lith_1
{
strings:
	$a0 = { 5c029a0d00cf015589e531c09acd025c02c606542e009a1e095c0209c07e03e88afbe810f9e80bfae81ff7e80d }


condition:
	$a0
}