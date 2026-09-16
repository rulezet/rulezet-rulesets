rule Win_Trojan_Startpage_478
{
strings:
	$a0 = { 8d542444680401000052ff1528104000bfa820400083c9ff33c0 }


condition:
	$a0
}