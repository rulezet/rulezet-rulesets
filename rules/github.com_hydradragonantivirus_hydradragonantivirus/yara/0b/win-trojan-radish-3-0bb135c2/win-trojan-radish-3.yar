rule Win_Trojan_Radish_3
{
strings:
	$a0 = { 57eb0190bad521eb019033c9eb0190b8023ceb0190cd21eb019093eb0190b440eb0190b9 }


condition:
	$a0
}