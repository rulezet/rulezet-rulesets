rule Win_Trojan_Delf_1135
{
strings:
	$a0 = { 6a00a15086400050b8dc654000506a03e8a7e2ffffa3e0864000833de0864000000f95c0f6d81bc0c3 }


condition:
	$a0
}