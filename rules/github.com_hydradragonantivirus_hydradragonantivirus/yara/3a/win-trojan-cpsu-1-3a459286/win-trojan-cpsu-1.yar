rule Win_Trojan_CPSU_1
{
strings:
	$a0 = { 5f1e06505351525683ef2b8d85e3008cd28ccb8edb9c1e508bec8b65208b5d1e8ed38d8561001e5083ec04b80c }


condition:
	$a0
}