rule Win_Trojan_Agent_35418
{
strings:
	$a0 = { 558bece8d8a2ffffe8030000005dc3cc558bec6afe685456460068d0ec430064a1 }


condition:
	$a0
}