rule Win_Trojan_Pyros_1
{
strings:
	$a0 = { 9ecf00cd21b4408d960700b950098b9ecf00cd21b8004233c933d28b9ecf00cd21b4408d96460f }


condition:
	$a0
}