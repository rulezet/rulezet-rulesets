rule Win_Trojan_Windows_1
{
strings:
	$a0 = { 457516817c0c0203750f807c3204750981 }


condition:
	$a0
}