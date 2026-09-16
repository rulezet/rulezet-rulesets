rule Ruby_MARK_5__32_lil_AND_
{
strings:
	$a0 = { 91606c45[0-20]c31071aa[0-20]1f000000[0-20]1b000000 }

condition:
	$a0
}