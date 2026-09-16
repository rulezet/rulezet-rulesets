rule Win_Trojan_Gisela_1
{
strings:
	$a0 = { a5008c06a7006825215886c4ba2001cd21b8004b0410 }


condition:
	$a0
}