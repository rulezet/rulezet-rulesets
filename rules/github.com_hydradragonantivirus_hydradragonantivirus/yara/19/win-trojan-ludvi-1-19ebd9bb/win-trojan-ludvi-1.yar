rule Win_Trojan_Ludvi_1
{
strings:
	$a0 = { 9a0000d5005589e5b800029acd02d50081ec0002bf3c070e57bf7c051e5768ff009a5408d500803e7d054c7403e9cc01 }


condition:
	$a0
}