rule Win_Trojan_BadCOM_3
{
strings:
	$a0 = { f7f140a33801b4408b1e4001b9100029d1ba4401cd21721fb800428b1e4001b90000ba0000cd }


condition:
	$a0
}