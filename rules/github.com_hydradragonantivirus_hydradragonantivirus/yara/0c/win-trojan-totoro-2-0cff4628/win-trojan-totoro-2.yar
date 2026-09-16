rule Win_Trojan_Totoro_2
{
strings:
	$a0 = { cd21722333c933d2b80242cd212ec706050100000504002ea303010e1fbad406b90400b440cd21 }


condition:
	$a0
}