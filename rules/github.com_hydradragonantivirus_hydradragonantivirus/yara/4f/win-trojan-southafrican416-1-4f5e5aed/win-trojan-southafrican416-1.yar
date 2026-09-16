rule Win_Trojan_SouthAfrican416_1
{
strings:
	$a0 = { 0301ff360501b43fb90300ba0301 }


condition:
	$a0
}