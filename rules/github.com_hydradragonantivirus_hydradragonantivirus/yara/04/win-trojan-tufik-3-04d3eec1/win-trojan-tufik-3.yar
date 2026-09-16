rule Win_Trojan_Tufik_3
{
strings:
	$a0 = { e8000000005b81eb193a4000ff3424e8bffeffff }


condition:
	$a0
}