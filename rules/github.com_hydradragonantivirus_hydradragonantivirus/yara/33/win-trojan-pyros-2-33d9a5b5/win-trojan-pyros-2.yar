rule Win_Trojan_Pyros_2
{
strings:
	$a0 = { 408b9ecf00b950098d960700cd21b800428b9ecf0033c933d2cd21b4408b9ecf00b906008d96d8 }


condition:
	$a0
}