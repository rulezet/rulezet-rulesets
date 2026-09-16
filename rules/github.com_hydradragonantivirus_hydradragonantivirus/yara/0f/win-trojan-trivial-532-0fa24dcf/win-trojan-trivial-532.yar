rule Win_Trojan_Trivial_532
{
strings:
	$a0 = { b44eba5d01b90700eb[0-3]8bd8b8????b90000cd21eb[0-6]b440b9??00ba0001cd21eb }


condition:
	$a0
}