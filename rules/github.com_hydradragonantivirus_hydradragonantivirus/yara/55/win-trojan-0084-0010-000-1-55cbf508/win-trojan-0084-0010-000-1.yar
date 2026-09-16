rule Win_Trojan__0084_0010_000_1
{
strings:
	$a0 = { fa26a3900026891e9200fbc39c2eff1e0205c3b8004233c933d2e8efffc3b43ee8e9ffc3a11d }


condition:
	$a0
}