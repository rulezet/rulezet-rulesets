rule Win_Trojan_Decimation_1
{
strings:
	$a0 = { 50b82a04508a44049850e8fe0b83c4063d01007518b8010050b83e05508a44049850e8e60b }


condition:
	$a0
}