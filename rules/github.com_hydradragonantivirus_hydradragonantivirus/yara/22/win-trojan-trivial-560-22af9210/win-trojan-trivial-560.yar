rule Win_Trojan_Trivial_560
{
strings:
	$a0 = { b91f00be????8034??46e2fab138cd21c3 }


condition:
	$a0
}