rule Win_Trojan_Feist_1
{
strings:
	$a0 = { d3e25233d2b91000f7f18bca5a03d02b16a60383ea10 }


condition:
	$a0
}