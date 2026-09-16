rule Win_Trojan_IL_1
{
strings:
	$a0 = { 50fbeb159a33cc96000c00494cb90006ac32c3d1c3aae2f8c35b58331e4b00330732066800 }


condition:
	$a0
}