rule Win_Trojan_ACME_1
{
strings:
	$a0 = { 8b0e2701b44ecd21720fe86bffe892ffe89bffb44fcd2175f1e845ffbe9903cd2e }


condition:
	$a0
}