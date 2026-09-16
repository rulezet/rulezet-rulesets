rule Win_Trojan_Digipol_1
{
strings:
	$a0 = { 8b8620048dbe0301b9850131054747e2fac3 }


condition:
	$a0
}