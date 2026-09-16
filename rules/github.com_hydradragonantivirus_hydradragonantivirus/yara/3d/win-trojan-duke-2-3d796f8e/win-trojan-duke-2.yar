rule Win_Trojan_Duke_2
{
strings:
	$a0 = { 7a205b41424d20312e332064656d6f5d2062792044756b652f534d4625250d }


condition:
	$a0
}