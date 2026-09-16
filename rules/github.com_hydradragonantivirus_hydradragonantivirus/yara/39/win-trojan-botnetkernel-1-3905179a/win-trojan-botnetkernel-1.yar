rule Win_Trojan_BotnetKernel_1
{
strings:
	$a0 = { c745e4000000008b45e483c0018945e4837de4337ef1 }


condition:
	$a0
}