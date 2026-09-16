rule Win_Trojan_Problem_2
{
strings:
	$a0 = { 5e83ee031eb82135cd21fa2e8c844f032e899c4d038cd82e018494002e0184880048eb0d26 }


condition:
	$a0
}