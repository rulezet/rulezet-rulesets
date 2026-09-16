rule Win_Dropper_Agent_35860
{
strings:
	$a0 = { 52535733ff5056510f84baffffffd8c8cf15a38b0d050ed0e6c536663db4c7d5cac1ca947738267c0adb667d0535bc90 }


condition:
	$a0
}