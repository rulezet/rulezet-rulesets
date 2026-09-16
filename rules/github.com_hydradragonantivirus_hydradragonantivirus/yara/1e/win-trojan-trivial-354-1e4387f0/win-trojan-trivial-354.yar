rule Win_Trojan_Trivial_354
{
strings:
	$a0 = { ba4705cd2106c360b8013dcd2172159090931e0e1fb440ba0005b94d00cd21b43ecd211f61 }


condition:
	$a0
}