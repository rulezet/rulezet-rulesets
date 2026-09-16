rule Win_Trojan_Clock_1
{
strings:
	$a0 = { 741bb90700ba8000cd13b801020e07bb0002ba8000b90600cd13eb19 }


condition:
	$a0
}