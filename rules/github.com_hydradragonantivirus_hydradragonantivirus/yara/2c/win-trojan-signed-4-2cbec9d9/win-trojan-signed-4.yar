rule Win_Trojan_Signed_4
{
strings:
	$a0 = { 0e58072e8c1e0a04501f8a163100bb3700803e31000074 }


condition:
	$a0
}