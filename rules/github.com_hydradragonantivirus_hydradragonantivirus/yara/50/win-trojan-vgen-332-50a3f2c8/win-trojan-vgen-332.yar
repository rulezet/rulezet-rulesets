rule Win_Trojan_VGEN_332
{
strings:
	$a0 = { 70038cca03d08cc981c1c60951b90100510606b1ff518cd383eb1853b142fc518cd5be3e0033ff4d8ec58eda4ab108 }


condition:
	$a0
}