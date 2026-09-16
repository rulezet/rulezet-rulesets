rule Win_Trojan_SillyC_110
{
strings:
	$a0 = { 16010181c20301b9df00b440cd21bad50001f231c9b80042cd21b904008d56fab440cd21c646fa }


condition:
	$a0
}