rule Win_Trojan_Grosser_2
{
strings:
	$a0 = { 8cca03d08cc981c10a0251b90100510606b1ff518cd383eb1853b142fc518cd5be3e0033ff4d8ec58eda4ab108 }


condition:
	$a0
}