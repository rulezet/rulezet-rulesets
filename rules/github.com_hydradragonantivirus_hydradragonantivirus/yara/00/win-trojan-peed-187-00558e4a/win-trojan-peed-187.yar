rule Win_Trojan_Peed_187
{
strings:
	$a0 = { 558bec83ec305356570fb6f9f7d985d80fbef10fb6d24a4f33 }


condition:
	$a0
}