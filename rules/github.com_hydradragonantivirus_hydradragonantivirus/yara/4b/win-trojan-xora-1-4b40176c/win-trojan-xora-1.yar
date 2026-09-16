rule Win_Trojan_XorA_1
{
strings:
	$a0 = { 012ec70490905eba0001b89f03b109d3e840b109d3e08bc8b80040cd212e8b0e2e012e8b1630 }


condition:
	$a0
}