rule Win_Trojan_SFT_2
{
strings:
	$a0 = { cd2150558becc7460200435d58babe0133c9350100cd21720cb43ffec4bacd0180f401cd21 }


condition:
	$a0
}