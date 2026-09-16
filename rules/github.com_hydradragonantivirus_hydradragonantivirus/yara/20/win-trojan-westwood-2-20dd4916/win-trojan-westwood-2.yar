rule Win_Trojan_Westwood_2
{
strings:
	$a0 = { cd218cc80510008ed0bc100750b8 }


condition:
	$a0
}