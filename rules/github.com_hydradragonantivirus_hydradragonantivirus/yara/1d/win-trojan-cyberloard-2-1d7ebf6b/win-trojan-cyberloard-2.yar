rule Win_Trojan_Cyberloard_2
{
strings:
	$a0 = { 0e8a018b1e8801b97d01ba0001b440cd21803e8a01007403e9ff00e92d01 }


condition:
	$a0
}