rule Win_Trojan_VB_1017
{
strings:
	$a0 = { 43003a005c00730065006c0069006c006c0033002e006200610074 }


condition:
	$a0
}