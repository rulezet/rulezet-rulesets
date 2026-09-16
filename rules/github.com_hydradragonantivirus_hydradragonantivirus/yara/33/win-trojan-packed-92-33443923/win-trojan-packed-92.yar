rule Win_Trojan_Packed_92
{
strings:
	$a0 = { 161412ffc6bbabffcbaa88ffd5b593ffe3c8aaffe7d3bbffbe8c42ffbc8000ffcb9103ffd5a232ffdcb468ffe3c68dffddc69eff7dc9e1ffa7eaf9ff9ae7faff83dffbff67d4f6ff3dc8f9ff2ab8fbff89c1d8ffefe1cdffedd9be }

	$a1 = { e803000000eb01e?bb55000000e803000000eb01e?e88e000000e803000000eb01??e881000000 }


condition:
	$a0 and $a1
}