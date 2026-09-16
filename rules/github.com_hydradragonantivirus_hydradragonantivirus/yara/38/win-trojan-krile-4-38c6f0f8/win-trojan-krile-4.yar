rule Win_Trojan_Krile_4
{
strings:
	$a0 = { 8cca03d08cc981c1550551b90d00510606b1ff518cd383eb1853b14051fc8cd5be3f0033ff4d8ec58eda4ab9080050ad355454abe2f9584879e68edd0e0733ffbe0900cb }


condition:
	$a0
}