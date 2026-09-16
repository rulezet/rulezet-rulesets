rule Win_Trojan_BlackEnd_1
{
strings:
	$a0 = { 050055a205000000ffff000000000f0300000a0000007008 }


condition:
	$a0
}