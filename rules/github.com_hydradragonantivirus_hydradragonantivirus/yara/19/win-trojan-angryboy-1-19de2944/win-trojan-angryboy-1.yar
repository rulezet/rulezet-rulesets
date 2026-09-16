rule Win_Trojan_AngryBoy_1
{
strings:
	$a0 = { 1e060e1f8a263400ba4b00b90908e80400eb189001515657061e078bf28bfafcac32c4aae2fa07 }


condition:
	$a0
}