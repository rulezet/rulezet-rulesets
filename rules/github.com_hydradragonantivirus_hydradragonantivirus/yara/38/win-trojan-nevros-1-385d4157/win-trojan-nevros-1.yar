rule Win_Trojan_Nevros_1
{
strings:
	$a0 = { b9d5012e311b47e5428bf0e5423bc67518a480ad88ab8ee4942da493a12c7745622d83ae90 }


condition:
	$a0
}