rule Win_Trojan_Sentinel_3
{
strings:
	$a0 = { 2ea30001ac2ea2020189ec5db800 }


condition:
	$a0
}