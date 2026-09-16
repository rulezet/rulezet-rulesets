rule Win_Trojan_Deflo_1
{
strings:
	$a0 = { fe8bc4e2d272fa83f9cd2546800047ff0048fffe33edda39faff00e500da3afa00001741e20042c7 }


condition:
	$a0
}