rule Win_Trojan_Peed_177
{
strings:
	$a0 = { e80c000000f7db29dff7db01de89c3eb1b59e886000000bfd4??4000bb59f3ffff81c39e0c000001c789f89681c3e2d9 }


condition:
	$a0
}