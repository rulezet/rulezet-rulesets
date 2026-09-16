rule Win_Trojan_Vundo_33
{
strings:
	$a0 = { 60e8f813000038117677e44d02135049 }


condition:
	$a0
}