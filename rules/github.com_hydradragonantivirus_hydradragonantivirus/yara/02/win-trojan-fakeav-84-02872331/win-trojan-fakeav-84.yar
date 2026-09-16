rule Win_Trojan_FakeAV_84
{
strings:
	$a0 = { 8d6424fcc70424b18d1d29893c24e9970200008bf683c4048db0000000008b36 }

	$a1 = { 2b5041443234 }


condition:
	$a0 and $a1
}