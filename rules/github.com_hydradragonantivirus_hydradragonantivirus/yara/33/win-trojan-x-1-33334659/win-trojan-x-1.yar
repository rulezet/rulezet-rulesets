rule Win_Trojan_X_1
{
strings:
	$a0 = { 5b582d325d004943452d392c202d3c2041524356203e2d }


condition:
	$a0
}