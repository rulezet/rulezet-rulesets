rule Win_Trojan_Sankei_6
{
strings:
	$a0 = { e8000000005d81ed051040008db52c104000b9d201000056 }


condition:
	$a0
}