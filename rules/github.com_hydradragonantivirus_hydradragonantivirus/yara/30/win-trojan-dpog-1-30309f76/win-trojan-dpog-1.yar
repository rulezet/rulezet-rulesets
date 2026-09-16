rule Win_Trojan_DPOG_1
{
strings:
	$a0 = { 2044756b652f534d469a000040005589e5b800019acd02400081ec0001bf33020e57bf52001e }


condition:
	$a0
}