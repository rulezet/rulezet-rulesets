rule Win_Trojan_Form_4
{
strings:
	$a0 = { c0078ed833f626832e13040226a11304b106d3e08ec033 }


condition:
	$a0
}