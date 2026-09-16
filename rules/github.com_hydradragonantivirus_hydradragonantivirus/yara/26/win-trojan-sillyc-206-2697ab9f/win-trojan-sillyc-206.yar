rule Win_Trojan_SillyC_206
{
strings:
	$a0 = { b502b4408b1ead02b90300bab402cd21a1940233d2bb1000f7f3a3b702b44232c08b1ead }


condition:
	$a0
}