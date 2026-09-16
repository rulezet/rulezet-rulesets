rule Win_Trojan_Sankei_2
{
strings:
	$a0 = { e8000000005d81ed051040008db52c104000b94d030000568bfead33 }

	$a1 = { 57696e39782e53616e6b6569 }


condition:
	$a0 and $a1
}