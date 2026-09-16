rule Win_Trojan_Kvapavka_1
{
strings:
	$a0 = { 568a944d03b94c038a0430d0880446e2f7e9eafc }


condition:
	$a0
}