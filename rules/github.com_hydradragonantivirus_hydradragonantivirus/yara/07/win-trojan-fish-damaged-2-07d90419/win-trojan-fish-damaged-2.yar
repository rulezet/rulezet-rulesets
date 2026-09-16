rule Win_Trojan_Fish_damaged_2
{
strings:
	$a0 = { e800005b81eba90db9580d2e80371843e2f92efe8fb3007403e960f4c3 }


condition:
	$a0
}