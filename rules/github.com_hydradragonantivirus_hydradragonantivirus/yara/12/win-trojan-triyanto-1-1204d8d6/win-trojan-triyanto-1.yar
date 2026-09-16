rule Win_Trojan_Triyanto_1
{
strings:
	$a0 = { ff01ba0001b910002e2b0e27039c2eff1e06017203eb0490e9d302b4402e8b1eff01ba0001b9ba }


condition:
	$a0
}