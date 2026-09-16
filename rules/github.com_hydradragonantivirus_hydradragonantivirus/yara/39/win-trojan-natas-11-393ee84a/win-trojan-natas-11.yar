rule Win_Trojan_Natas_11
{
strings:
	$a0 = { 8d2e94abbf8604f9f583d7628d0efc08be2d5af8fc112d81e90100f887c287d681dffeff83c90089e82e780279e5 }


condition:
	$a0
}