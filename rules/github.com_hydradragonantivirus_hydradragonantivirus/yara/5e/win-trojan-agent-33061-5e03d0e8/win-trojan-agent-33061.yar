rule Win_Trojan_Agent_33061
{
strings:
	$a0 = { e82d2c17d718c8ee287c2665700d018708ffffffffbf6e3dcc5652c63ac4962fc39f9e08525d5912706f42e2ebba931dfc099ca1cb7f61a1ff2c1c2508638d9de1283c1d684d0484b1cf }


condition:
	$a0
}