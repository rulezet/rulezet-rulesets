rule Win_Trojan_Agent_35526
{
strings:
	$a0 = { 558bec83c4f86033cfc1d30833ff33cd9081 }

	$a1 = { 663453626d24631cf468d27c }


condition:
	$a0 and $a1
}