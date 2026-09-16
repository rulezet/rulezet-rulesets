rule Win_Trojan_Small_4050
{
strings:
	$a0 = { eb0e89f82d315d22fd05555522fdeb38eb0b59535557e863000000eb20eb19ba08????00ff141a8d88555512ff294d00 }


condition:
	$a0
}