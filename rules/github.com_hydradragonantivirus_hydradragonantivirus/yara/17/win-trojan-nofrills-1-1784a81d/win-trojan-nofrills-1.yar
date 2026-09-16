rule Win_Trojan_NoFrills_1
{
strings:
	$a0 = { 547504b80510cf80fc4b741880fc3d741380fc43740e }


condition:
	$a0
}