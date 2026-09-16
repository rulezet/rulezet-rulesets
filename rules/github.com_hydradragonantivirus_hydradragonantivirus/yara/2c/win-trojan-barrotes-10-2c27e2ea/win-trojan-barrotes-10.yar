rule Win_Trojan_Barrotes_10
{
strings:
	$a0 = { 7403e9ba01505351521e0656572e891647012e8c1e }


condition:
	$a0
}