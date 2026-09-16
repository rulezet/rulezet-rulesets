rule Win_Trojan_Rattler_1
{
strings:
	$a0 = { 58e07a0b89ce380d5286ca86d284d833ca5083d07d00b708095fadadaccb260b5c128bca185a26f77c10c32e83160a08 }


condition:
	$a0
}