rule Win_Trojan_EE_2
{
strings:
	$a0 = { 80fc0a720c241f7508b8ed0e40cd10ebf880c40626 }


condition:
	$a0
}