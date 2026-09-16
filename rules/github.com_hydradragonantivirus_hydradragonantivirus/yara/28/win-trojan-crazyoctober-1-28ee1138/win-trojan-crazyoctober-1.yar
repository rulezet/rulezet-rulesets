rule Win_Trojan_CrazyOctober_1
{
strings:
	$a0 = { b42acd213c057403e9a900fc0e1fbe2401b99200ac2c85b4028ad0cd21e2f5e99200cdeea5a6a5cea5e6f2a5f9ed }


condition:
	$a0
}