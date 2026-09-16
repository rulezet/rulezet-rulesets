rule Win_Spyware_58589_1
{
strings:
	$a0 = { 558bec54686f810bea687c1e3073505050536a0566810d9c1101105a2f33c057 }


condition:
	$a0
}