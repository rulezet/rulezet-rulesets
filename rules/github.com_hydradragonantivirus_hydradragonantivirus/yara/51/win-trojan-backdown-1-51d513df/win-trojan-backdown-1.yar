rule Win_Trojan_Backdown_1
{
strings:
	$a0 = { a35859400033c05568023f400064ff306489206a006a006a006a00688c3f4000a15859400050e882feffff }


condition:
	$a0
}