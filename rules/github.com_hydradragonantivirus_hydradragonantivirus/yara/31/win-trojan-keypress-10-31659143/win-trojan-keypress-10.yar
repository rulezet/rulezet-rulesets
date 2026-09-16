rule Win_Trojan_Keypress_10
{
strings:
	$a0 = { 8ccb031e020153bb3b0153cb }


condition:
	$a0
}