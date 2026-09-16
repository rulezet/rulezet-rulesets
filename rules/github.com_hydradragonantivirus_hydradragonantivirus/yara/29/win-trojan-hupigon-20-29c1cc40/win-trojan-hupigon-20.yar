rule Win_Trojan_Hupigon_20
{
strings:
	$a0 = { b8642c4100ba40004100e86842ffff }


condition:
	$a0
}