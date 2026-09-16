rule Win_Trojan_Variola_1
{
strings:
	$a0 = { d9d1e94b8a248a0032e132c126880526882146474be2ecc39090909090909090 }


condition:
	$a0
}