rule Win_Trojan_Anthrax_7
{
strings:
	$a0 = { cd2f585a870487540252505156a0 }


condition:
	$a0
}