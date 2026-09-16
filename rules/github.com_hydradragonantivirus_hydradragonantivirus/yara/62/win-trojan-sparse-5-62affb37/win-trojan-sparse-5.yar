rule Win_Trojan_Sparse_5
{
strings:
	$a0 = { 554bcd213d31127476b82135cd21b0 }


condition:
	$a0
}