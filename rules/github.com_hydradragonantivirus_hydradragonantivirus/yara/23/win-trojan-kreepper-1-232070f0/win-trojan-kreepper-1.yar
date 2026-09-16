rule Win_Trojan_Kreepper_1
{
strings:
	$a0 = { 60e8000000005883e83d508db800b0fcff578db0e8 }


condition:
	$a0
}