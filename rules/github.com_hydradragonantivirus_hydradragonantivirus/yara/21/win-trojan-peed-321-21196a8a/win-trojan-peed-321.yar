rule Win_Trojan_Peed_321
{
strings:
	$a0 = { 558bec83ec0c535657[0-200]cccccccccccccc555756535152fc8b74241c8b7c242483cdff31c9eb16909090 }


condition:
	$a0
}