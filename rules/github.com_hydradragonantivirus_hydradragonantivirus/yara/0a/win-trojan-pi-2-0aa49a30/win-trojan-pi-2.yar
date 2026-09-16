rule Win_Trojan_PI_2
{
strings:
	$a0 = { b80040cd2133c933d2b80242cd2133d2b89d07b109d3e840b109d3e08bc8b80040cd211fb80157 }


condition:
	$a0
}