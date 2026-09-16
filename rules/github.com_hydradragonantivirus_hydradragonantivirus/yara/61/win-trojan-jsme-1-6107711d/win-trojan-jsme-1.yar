rule Win_Trojan_Jsme_1
{
strings:
	$a0 = { 50000775d7c60660052ec606610565c606620578c606630565bf58051e57b83f0050bf2a0e1e }


condition:
	$a0
}