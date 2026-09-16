rule Win_Trojan_CheckSum_1
{
strings:
	$a0 = { 03006490832e020064908ec056578bf5bf0000b92106 }


condition:
	$a0
}