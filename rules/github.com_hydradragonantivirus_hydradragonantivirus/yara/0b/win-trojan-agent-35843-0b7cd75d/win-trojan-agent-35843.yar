rule Win_Trojan_Agent_35843
{
strings:
	$a0 = { 442408706f7465[0-150]4424086d636573[0-150]2442656275 }


condition:
	$a0
}