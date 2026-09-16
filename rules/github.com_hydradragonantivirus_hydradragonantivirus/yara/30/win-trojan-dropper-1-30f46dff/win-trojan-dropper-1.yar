rule Win_Trojan_Dropper_1
{
strings:
	$a0 = { 7003b82425cd21c606b9030090b42fcd }


condition:
	$a0
}