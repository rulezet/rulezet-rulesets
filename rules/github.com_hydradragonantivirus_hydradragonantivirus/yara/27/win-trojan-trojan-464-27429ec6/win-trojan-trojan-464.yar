rule Win_Trojan_Trojan_464
{
strings:
	$a0 = { a5c686ae0832b41a8d968308cd21b447b2008db6 }


condition:
	$a0
}