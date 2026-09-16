rule Win_Trojan_Trojan_425
{
strings:
	$a0 = { a5a5a5a5c686??????b41a8d96????cd21b447b2008db6 }


condition:
	$a0
}