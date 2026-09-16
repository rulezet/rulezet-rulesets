rule Win_Trojan_Doshunter_2
{
strings:
	$a0 = { bb3901b46328274381fb590175f7b80006 }


condition:
	$a0
}