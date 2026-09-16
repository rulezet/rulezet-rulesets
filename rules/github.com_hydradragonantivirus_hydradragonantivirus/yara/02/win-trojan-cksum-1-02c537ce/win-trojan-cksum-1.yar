rule Win_Trojan_CKSum_1
{
strings:
	$a0 = { 42e843025a59b440e83c0272023bc1c3 }


condition:
	$a0
}