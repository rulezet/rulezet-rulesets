rule Win_Trojan_Trojan_209
{
strings:
	$a0 = { a4c686490903b41a8d961e09cd21b44790b2008db6de08 }


condition:
	$a0
}