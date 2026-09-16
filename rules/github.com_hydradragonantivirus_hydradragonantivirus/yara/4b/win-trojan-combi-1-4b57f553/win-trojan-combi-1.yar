rule Win_Trojan_Combi_1
{
strings:
	$a0 = { cd21b402b9010032f6bb0301cd26720383c402c3b42c }


condition:
	$a0
}