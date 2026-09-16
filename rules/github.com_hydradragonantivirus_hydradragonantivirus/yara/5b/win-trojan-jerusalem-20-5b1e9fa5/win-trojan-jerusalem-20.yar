rule Win_Trojan_Jerusalem_20
{
strings:
	$a0 = { 4d5acd218cc805100050b8910050cb068cc02ea308002ea374000510002e010614002e01061000b8000bbb4d }


condition:
	$a0
}