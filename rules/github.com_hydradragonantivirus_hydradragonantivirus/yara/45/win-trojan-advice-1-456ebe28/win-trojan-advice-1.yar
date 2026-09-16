rule Win_Trojan_Advice_1
{
strings:
	$a0 = { be00015683c61890b8f10f2e803404464875f8e9a10b518fe8ef1b8f5a008ac78f5a02228e038f5a0c8ac78f5a0e }


condition:
	$a0
}