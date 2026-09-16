rule Win_Trojan_Billnted2_1
{
strings:
	$a0 = { 3e44003f7403e94bff833e4600017403e936ffbf720d1e57b00d5031c0509a54068c00bf27000e }


condition:
	$a0
}