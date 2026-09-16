rule Win_Trojan_Crypt_196
{
strings:
	$a0 = { 608d35bf5f5d3cc1db0b33f5f933db9066bbc4038d0da8fe3340685b104000f7d387d681 }

	$a1 = { 686b45524e }


condition:
	$a0 and $a1
}