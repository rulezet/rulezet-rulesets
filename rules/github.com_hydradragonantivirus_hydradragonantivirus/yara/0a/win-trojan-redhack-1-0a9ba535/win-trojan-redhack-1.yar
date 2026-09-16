rule Win_Trojan_Redhack_1
{
strings:
	$a0 = { be110180340d46e2fa03548ee40ecb0b910c569d0b3ecd83cd2bac2d0dae950c2bac2f0dae970c83d4f72bca0b2d0da60c }


condition:
	$a0
}