rule epTool_bgptbl__32_big_28_
{
strings:
	$a0 = { 00008faf001626d5000000130000053700000ae30000000b000000e9 }

condition:
	$a0
}