rule Win_Spyware_Small_1729
{
strings:
	$a0 = { 558bec83ec0868c01100106868200010ff1508200010 }


condition:
	$a0
}