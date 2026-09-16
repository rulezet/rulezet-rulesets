rule Win_Trojan__1708_0006_001_1
{
strings:
	$a0 = { 598d967f05cd2132c0e829008d96df04cd215a5980e1e080c91db80157cd211f5a59e80600b4 }


condition:
	$a0
}