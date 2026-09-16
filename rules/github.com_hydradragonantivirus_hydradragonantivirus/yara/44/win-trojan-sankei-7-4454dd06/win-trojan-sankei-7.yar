rule Win_Trojan_Sankei_7
{
strings:
	$a0 = { e8000000005d81ed051040008db52c104000b95c030000568b }


condition:
	$a0
}