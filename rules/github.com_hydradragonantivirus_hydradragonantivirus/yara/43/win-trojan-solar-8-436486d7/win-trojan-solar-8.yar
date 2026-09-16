rule Win_Trojan_Solar_8
{
strings:
	$a0 = { 8ec033ffb1622ef3a48ed9b3223b0174088701ab8cc08701ab07061f680000c3608bf2ac3d4d407533ad3ae1 }


condition:
	$a0
}