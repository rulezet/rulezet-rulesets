rule Win_Trojan_Bancos_869
{
strings:
	$a0 = { 8b1a8ac6790f2ce914c647be7ef036d6da33b3b6d6cbfb8d703b4ca6cfedef51a1d834b25d13b70746a1da9a474723afe93df823217efee922ff9b14f0c2233a7d }


condition:
	$a0
}