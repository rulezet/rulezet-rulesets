rule Win_Trojan_Kril_1
{
strings:
	$a0 = { c1db0551b90d00510606b1ff518cd383eb1853b14051fc8cd5be380033ff4d8ec58eda4ab90800 }


condition:
	$a0
}