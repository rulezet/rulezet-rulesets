rule Win_Trojan_Agent_32959
{
strings:
	$a0 = { 703a2f2f9a2e7a673136392e6e65742f7e797568 }


condition:
	$a0
}