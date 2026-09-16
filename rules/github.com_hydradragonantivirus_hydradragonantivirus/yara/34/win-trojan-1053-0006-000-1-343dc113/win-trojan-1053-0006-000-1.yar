rule Win_Trojan__1053_0006_000_1
{
strings:
	$a0 = { 0426302446e2fab440b94304061fba0300cd211f07c3b448bbde0fcd21c38e064e05b449cd21c3 }


condition:
	$a0
}