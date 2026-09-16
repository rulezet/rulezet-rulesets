rule Win_Trojan_VGEN_509
{
strings:
	$a0 = { 019050eb019053eb019051eb019052eb019056eb019057eb0190bad521eb019033c9eb0190b8023ceb0190cd21eb }


condition:
	$a0
}