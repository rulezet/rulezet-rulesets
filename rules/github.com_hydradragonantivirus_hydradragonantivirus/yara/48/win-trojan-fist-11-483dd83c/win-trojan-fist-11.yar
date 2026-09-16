rule Win_Trojan_Fist_11
{
strings:
	$a0 = { c08ed88ed0bc007cfb832e130403cd1293b106d3e3538ec3b8bd005033dbb90200ba8000b80202cd13 }


condition:
	$a0
}