rule Win_Trojan_Small_5328
{
strings:
	$a0 = { 170ee2b7a81bea59fd4fabe6e891ff59b745e16f2b4ded2d943fb623176f992d9c3faa2dee90f69e149e73d2fd2072d1f94aed4ee71bbaa66b1d42ffb196fda203198966b745792dac3fb2f0636f }


condition:
	$a0
}