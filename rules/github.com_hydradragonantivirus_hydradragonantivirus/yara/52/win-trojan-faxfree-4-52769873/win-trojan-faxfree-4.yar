rule Win_Trojan_FaxFree_4
{
strings:
	$a0 = { 2687060c00508cc82687060e0050cc589d582687060e00 }


condition:
	$a0
}