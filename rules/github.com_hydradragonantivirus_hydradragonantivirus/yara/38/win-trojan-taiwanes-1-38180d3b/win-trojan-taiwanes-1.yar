rule Win_Trojan_Taiwanes_1
{
strings:
	$a0 = { 20004a0025206a000100ad0004005c2a2e2a11004140d4000100de0020007400bf0042406b }


condition:
	$a0
}