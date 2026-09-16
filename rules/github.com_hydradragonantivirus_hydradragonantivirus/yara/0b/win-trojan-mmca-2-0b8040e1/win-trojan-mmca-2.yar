rule Win_Trojan_MMCA_2
{
strings:
	$a0 = { aae8acd953e4b36942f51598af1908ec18b861cb8a61d3ee8a2ed116e3cc2d9752604d9f5b52 }


condition:
	$a0
}