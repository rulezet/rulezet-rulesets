rule Win_Trojan_Form_5
{
strings:
	$a0 = { 13040226a11304b106d3e08ec033ffb9ff00fcf3a5 }


condition:
	$a0
}