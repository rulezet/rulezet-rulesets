rule Win_Trojan_BG_1
{
strings:
	$a0 = { 510f8edabe1b008004e7802e0c00f183c60181fe570876ef }


condition:
	$a0
}