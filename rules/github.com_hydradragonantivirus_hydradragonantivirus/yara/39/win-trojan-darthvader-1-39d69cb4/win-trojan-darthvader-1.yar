rule Win_Trojan_DarthVader_1
{
strings:
	$a0 = { 0172532e8c1e000c2e8916020cb820 }


condition:
	$a0
}