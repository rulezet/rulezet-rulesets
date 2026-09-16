rule Win_Trojan_Remut_1
{
strings:
	$a0 = { cd215251b002e89700fec4a3960553e88d035b25ff01ba48eeb9a00f03c8b440cd2132c0e8 }


condition:
	$a0
}