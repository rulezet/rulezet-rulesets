rule Win_Trojan_Gen_130
{
strings:
	$a0 = { 115b595ae800005d81ed0b00b87777cd213d8888745cb4 }


condition:
	$a0
}