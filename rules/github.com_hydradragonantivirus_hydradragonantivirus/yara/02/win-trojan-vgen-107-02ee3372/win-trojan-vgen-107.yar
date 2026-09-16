rule Win_Trojan_VGEN_107
{
strings:
	$a0 = { c40583c61946b1002ed20c2e8034004875f381eedd0556eb0c9090909090cd206666000000b8bf30cd213dffff75 }


condition:
	$a0
}