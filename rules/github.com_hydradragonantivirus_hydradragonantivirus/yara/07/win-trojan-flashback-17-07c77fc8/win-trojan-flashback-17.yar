rule Win_Trojan_Flashback_17
{
strings:
	$a0 = { 557365722d4167656e74007762002f62696e2f736800 }


condition:
	$a0
}