rule Win_Trojan_PowerPump_2
{
strings:
	$a0 = { 01508d867cf950e8431b5959b8780150b86e0150e8dc0059598946e8837efc00 }


condition:
	$a0
}