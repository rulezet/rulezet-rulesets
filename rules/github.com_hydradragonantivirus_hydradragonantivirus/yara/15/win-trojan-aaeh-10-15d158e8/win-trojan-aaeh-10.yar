rule Win_Trojan_AAEH_10
{
strings:
	$a0 = { 5368696b697269 }

	$a1 = { 94481c0ef45a9d076744eb2e7b20d515d86176f71d4d2976ac52b2ca4b7d8f8212de4d6859f5832ebf03984d820a5c8d }


condition:
	$a0 and $a1
}