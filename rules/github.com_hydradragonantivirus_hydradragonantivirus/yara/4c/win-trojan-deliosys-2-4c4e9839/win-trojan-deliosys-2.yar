rule Win_Trojan_DelIosys_2
{
strings:
	$a0 = { 0143ba1401b90600cd217206b441cd217200c3633a5c696f2e73797300 }


condition:
	$a0
}