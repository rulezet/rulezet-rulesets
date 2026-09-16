rule Win_Trojan_Rubbit_1
{
strings:
	$a0 = { 0e0e1f078bde81c62b008bfeb91b0cacc0c804aa }


condition:
	$a0
}