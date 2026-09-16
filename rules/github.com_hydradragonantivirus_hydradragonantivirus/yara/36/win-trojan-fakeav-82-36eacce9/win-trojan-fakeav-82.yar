rule Win_Trojan_FakeAV_82
{
strings:
	$a0 = { 558becb9050000006a006a004975f95356578bd88b355079 }

	$a1 = { 526170696420416e74697669727573 }


condition:
	$a0 and $a1
}