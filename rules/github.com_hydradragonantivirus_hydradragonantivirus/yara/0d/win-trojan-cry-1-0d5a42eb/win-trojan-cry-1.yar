rule Win_Trojan_Cry_1
{
strings:
	$a0 = { 8db635018bfeb9f10166ad6603c366ab6681c301f491412ec6863201ebe2eaeb0180 }


condition:
	$a0
}