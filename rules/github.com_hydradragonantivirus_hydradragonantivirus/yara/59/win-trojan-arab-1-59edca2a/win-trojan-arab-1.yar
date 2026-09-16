rule Win_Trojan_Arab_1
{
strings:
	$a0 = { 3d004b75368bec8b76008b7e028cc98e }


condition:
	$a0
}