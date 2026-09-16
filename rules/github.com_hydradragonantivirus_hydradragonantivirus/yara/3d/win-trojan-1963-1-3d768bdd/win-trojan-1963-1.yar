rule Win_Trojan_1963_1
{
strings:
	$a0 = { 1eb80312cd2f2e8c1e040933f68edebf }


condition:
	$a0
}