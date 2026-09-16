rule Win_Trojan_STL_1
{
strings:
	$a0 = { bc007c8becfb531f5683861388fccd12b106d3e0408ec006b80602b90c00ba8000cd13b82f00 }


condition:
	$a0
}