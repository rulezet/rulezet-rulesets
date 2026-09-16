rule Win_Trojan_JDC_1
{
strings:
	$a0 = { 27018a26ea048a0732c4cdde8807434983f90075 }


condition:
	$a0
}