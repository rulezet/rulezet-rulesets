rule Win_Trojan_Peed_18
{
strings:
	$a0 = { 89c381c3????400068a52aff0168a23aee0268a25ab63b6a2381c3ff23b11dff }


condition:
	$a0
}