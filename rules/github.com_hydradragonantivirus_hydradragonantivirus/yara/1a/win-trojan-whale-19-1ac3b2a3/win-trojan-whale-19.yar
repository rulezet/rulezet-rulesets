rule Win_Trojan_Whale_19
{
strings:
	$a0 = { e8f1ffb89f2329c3b91a0033c8e81600 }


condition:
	$a0
}