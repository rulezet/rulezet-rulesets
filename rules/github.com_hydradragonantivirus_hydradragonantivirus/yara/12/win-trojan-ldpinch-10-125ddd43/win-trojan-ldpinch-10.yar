rule Win_Trojan_Ldpinch_10
{
strings:
	$a0 = { 45484c4f206c1d6f63611d684d73742394062e??0175626a656374????50 }


condition:
	$a0
}