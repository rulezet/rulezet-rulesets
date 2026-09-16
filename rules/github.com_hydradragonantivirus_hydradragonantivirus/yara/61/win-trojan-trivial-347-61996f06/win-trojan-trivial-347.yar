rule Win_Trojan_Trivial_347
{
strings:
	$a0 = { b82125ba4205cd2106c360b8013dcd217213931e0e1fb440ba0005b94800cd21b43ecd211f61 }


condition:
	$a0
}