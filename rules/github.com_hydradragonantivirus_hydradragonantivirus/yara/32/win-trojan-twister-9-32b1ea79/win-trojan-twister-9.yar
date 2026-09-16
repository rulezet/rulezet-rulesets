rule Win_Trojan_Twister_9
{
strings:
	$a0 = { 56617961436f6e44696f7364650541626f7274 }


condition:
	$a0
}