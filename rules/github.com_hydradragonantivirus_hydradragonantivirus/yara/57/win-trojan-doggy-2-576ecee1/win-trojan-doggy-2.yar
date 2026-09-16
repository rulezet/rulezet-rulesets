rule Win_Trojan_Doggy_2
{
strings:
	$a0 = { 8cca03d08cc981c1510351b90100510606b1ff518cd383eb1853b142fc518cd5be310033ff4d8ec58eda4ab108 }


condition:
	$a0
}