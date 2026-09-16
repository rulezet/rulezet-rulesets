rule Win_Trojan_Natas_3
{
strings:
	$a0 = { 8d1ecc90c7c721ae8bc1bdb919b9ea0881ee96ad87d0299b5a41f7db83efff45e2f2 }


condition:
	$a0
}