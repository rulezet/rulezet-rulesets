rule Win_Trojan_Trojan_263
{
strings:
	$a0 = { 0e1f8d369004bf0001b92000f3a42ec6064903ff901f8d }


condition:
	$a0
}