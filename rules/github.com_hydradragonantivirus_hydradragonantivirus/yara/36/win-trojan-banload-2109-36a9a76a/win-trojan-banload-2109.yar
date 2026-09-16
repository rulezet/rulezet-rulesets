rule Win_Trojan_Banload_2109
{
strings:
	$a0 = { 60be003050008dbe00e0efffc787e49912009422ba0b5783cdffeb0e909090908a064688074701db75078b1e83 }


condition:
	$a0
}