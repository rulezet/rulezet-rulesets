rule Win_Trojan_Olen_1
{
strings:
	$a0 = { 072eff84b7012ec684ba010054583bc4750c2ec6849803002ec684ba01ff2ec6849906ffe84d032e899ccb02 }


condition:
	$a0
}