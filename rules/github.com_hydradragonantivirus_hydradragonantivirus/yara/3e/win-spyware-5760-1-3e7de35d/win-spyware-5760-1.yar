rule Win_Spyware_5760_1
{
strings:
	$a0 = { 558becb90f0000006a006a004975f953b830884000e8feb0ffffbb2c91400033c0 }


condition:
	$a0
}