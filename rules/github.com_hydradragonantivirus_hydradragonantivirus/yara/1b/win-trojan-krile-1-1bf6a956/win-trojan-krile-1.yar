rule Win_Trojan_Krile_1
{
strings:
	$a0 = { 13018cca03d08cc981c11b0551b90d00510606b1ff518cd383eb1853b14051fc8cd5be420033ff4d8ec58eda4ab908 }


condition:
	$a0
}