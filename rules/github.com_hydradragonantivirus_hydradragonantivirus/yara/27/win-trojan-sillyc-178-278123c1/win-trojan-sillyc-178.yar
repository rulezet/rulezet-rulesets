rule Win_Trojan_SillyC_178
{
strings:
	$a0 = { 89864e02b000e84700b440b904008d964d02cd21b002e83700b440b951018d960401cd21eb188d }


condition:
	$a0
}