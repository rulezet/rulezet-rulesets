rule Win_Trojan_E_45
{
strings:
	$a0 = { 3dffff75039d40cf80fc3d741180fc4b742980fc43 }


condition:
	$a0
}