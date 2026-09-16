rule Win_Trojan_Sality_1025
{
strings:
	$a0 = { 60e8000000005883e83d508db800f0fdff578db0e801000083cdff31db90909090 }


condition:
	$a0
}