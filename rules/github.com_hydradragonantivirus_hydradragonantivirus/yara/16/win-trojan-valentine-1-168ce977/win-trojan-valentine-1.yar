rule Win_Trojan_Valentine_1
{
strings:
	$a0 = { 3400b9e8082e8a860e002e30044649bf75f87402ebfac3e8e4ff5e5956cd }


condition:
	$a0
}