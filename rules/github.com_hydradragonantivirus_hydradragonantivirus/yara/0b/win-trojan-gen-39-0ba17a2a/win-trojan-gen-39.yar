rule Win_Trojan_Gen_39
{
strings:
	$a0 = { 014425014427803c00750c8b4401a300018a4403a202 }


condition:
	$a0
}