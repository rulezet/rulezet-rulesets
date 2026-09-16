rule Win_Trojan_Vdir_2
{
strings:
	$a0 = { 57e80100e95e81c6bb00eb02e803fc56a5a5a5a55e81eeaf00c704a5a5c74402a5a5b8013ebbadfecd2181f3ad }


condition:
	$a0
}