rule Win_Trojan_Peed_76
{
strings:
	$a0 = { b870b240008b0c248d542000 }


condition:
	$a0
}