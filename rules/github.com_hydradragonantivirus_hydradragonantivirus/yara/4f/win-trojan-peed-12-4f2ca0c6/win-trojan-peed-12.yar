rule Win_Trojan_Peed_12
{
strings:
	$a0 = { 89c381c3745843006a4281c3ff23511fff9301dcaee0b8944eed0152682ae1af }


condition:
	$a0
}