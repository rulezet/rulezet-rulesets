rule Win_Trojan_Dropper_63
{
strings:
	$a0 = { 336e6c7838716570733d222f6bac7469747474407474742b3d2b3d74742b5f747474 }


condition:
	$a0
}