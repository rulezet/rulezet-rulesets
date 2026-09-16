rule Win_Trojan_Blackhole_27
{
strings:
	$a0 = { 3c68313e6c6f6164696e67202e2e2e20706c6561736520776169742e2e2e2e203c2f68313e }


condition:
	$a0
}