rule Win_Trojan_Jerusalem_1
{
strings:
	$a0 = { 2e8b8d1100cd218cc80510008ed0 }


condition:
	$a0
}