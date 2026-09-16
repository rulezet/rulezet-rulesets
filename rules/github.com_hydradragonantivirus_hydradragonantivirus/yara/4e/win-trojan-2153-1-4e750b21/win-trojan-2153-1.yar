rule Win_Trojan_2153_1
{
strings:
	$a0 = { b38550b3c78a05b37d3422b36a8805b3d947b303e2ef }


condition:
	$a0
}