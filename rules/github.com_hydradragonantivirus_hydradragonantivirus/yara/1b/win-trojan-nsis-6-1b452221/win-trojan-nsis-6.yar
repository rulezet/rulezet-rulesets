rule Win_Trojan_NSIS_6
{
strings:
	$a0 = { 65786500fd9a805c4e534953646c2e646c6c00fd??8000687474703a2f2f[0-30]2f6d34736f66742f696e73 }


condition:
	$a0
}