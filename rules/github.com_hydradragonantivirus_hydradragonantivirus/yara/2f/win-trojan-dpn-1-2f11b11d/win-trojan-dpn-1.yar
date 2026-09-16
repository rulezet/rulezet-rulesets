rule Win_Trojan_DPN_1
{
strings:
	$a0 = { 1e18013d92fd7744a3e200b90300bae400b4409cff1e18017232b96c0233d2b4409cff1e1801 }


condition:
	$a0
}