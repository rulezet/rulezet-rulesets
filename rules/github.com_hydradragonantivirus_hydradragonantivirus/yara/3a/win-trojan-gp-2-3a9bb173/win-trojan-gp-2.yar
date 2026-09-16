rule Win_Trojan_GP_2
{
strings:
	$a0 = { 2e8b8d0700cd218cc80510008ed0 }


condition:
	$a0
}