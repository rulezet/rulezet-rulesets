rule Win_Trojan_Win95_3
{
strings:
	$a0 = { bf001000c0b8ff000000b9fffffffff2ae8bd90bc90f848000000081ff00c000c073 }


condition:
	$a0
}