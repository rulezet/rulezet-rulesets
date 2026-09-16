rule Win_Trojan_Predator_12
{
strings:
	$a0 = { 7cb83200b9b1282ed30dd1c147474875f6 }


condition:
	$a0
}