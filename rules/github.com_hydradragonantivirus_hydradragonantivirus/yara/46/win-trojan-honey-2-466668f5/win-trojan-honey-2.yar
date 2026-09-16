rule Win_Trojan_Honey_2
{
strings:
	$a0 = { 3d01e97409b44fe976ffb400cd21b802428b9c3b0133 }


condition:
	$a0
}