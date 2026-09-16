rule Win_Trojan_VGEN_459
{
strings:
	$a0 = { f2ae47061f8bf70e07bfc904e86603b8c0c0cd213dd0d075082e891e6904e99400b452cd2126 }


condition:
	$a0
}