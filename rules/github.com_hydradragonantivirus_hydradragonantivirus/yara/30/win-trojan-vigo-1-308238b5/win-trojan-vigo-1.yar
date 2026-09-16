rule Win_Trojan_Vigo_1
{
strings:
	$a0 = { 5731ff2ea0e5032e3003cc4781ffb903cc75f4e8f6fe2ea06c032ea2e5035f58c3 }


condition:
	$a0
}