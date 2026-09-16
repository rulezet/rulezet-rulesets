rule Win_Trojan_Lunch_III_1
{
strings:
	$a0 = { 1001bc449a31274381fb0f0475f7f820212526668d9513ffacdd376ade6a9713ff6a9665212113ff5d35b627521f }


condition:
	$a0
}