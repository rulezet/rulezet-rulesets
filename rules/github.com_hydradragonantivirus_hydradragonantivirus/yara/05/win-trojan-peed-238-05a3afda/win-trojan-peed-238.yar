rule Win_Trojan_Peed_238
{
strings:
	$a0 = { 558bec83ec10535657[0-30]6808??4000[0-100]b850254000 }


condition:
	$a0
}