rule Win_Trojan_Arara_2
{
strings:
	$a0 = { babd8987873101098b33030bc1d9d1e9c1cbcacdc1d9d1e9c1d9d1e9c1d9d1e9c1d9d1e9c8cbca }


condition:
	$a0
}