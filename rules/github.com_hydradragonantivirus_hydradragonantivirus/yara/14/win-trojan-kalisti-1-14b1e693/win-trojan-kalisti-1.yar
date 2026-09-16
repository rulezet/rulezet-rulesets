rule Win_Trojan_Kalisti_1
{
strings:
	$a0 = { 504500004c[0-7]4b616c6c69737469e000 }

	$a1 = { 010b01 }


condition:
	$a0 and $a1
}