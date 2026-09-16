rule Win_Trojan_Tiny_66
{
strings:
	$a0 = { 112ea30b02b440ba0001b90d01cd212ea10b0226894515b440ba0e02b90d01cd211f07619d }


condition:
	$a0
}