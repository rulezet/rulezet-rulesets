rule Win_Trojan_Buster_1
{
strings:
	$a0 = { b0e834adba????5259be????e8 }

	$a1 = { 2e300446e2fac3 }


condition:
	$a0 and $a1
}