rule Win_Trojan_Pojer_1
{
strings:
	$a0 = { 5e9e83ee0a9ebb260003de9e2e8a9436079eb90f072e30179e43e2f9 }


condition:
	$a0
}