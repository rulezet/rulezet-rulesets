rule Win_Trojan_Sparse_3
{
strings:
	$a0 = { cd213d31127476b82135cd21b0eaa20002891e01028c060302b82125ba0003cd21b44a0e07bbef00cd21b448bb0010cd2189c789c2b45089d3cd218edf }


condition:
	$a0
}