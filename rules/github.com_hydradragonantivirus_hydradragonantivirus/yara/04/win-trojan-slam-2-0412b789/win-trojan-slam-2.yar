rule Win_Trojan_Slam_2
{
strings:
	$a0 = { 8cca03d08cc981c11f0651b90d00510606b1ff518cd383eb1853b14051fc8cd5be3d0033ff4d8ec58eda4ab908 }


condition:
	$a0
}