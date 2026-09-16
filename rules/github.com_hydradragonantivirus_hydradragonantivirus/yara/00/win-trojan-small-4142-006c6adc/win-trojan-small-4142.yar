rule Win_Trojan_Small_4142
{
strings:
	$a0 = { 672d3eb232406d96b1eb19ae9fe989b2dce829aedc685cb2dce879b2dce819ee }


condition:
	$a0
}