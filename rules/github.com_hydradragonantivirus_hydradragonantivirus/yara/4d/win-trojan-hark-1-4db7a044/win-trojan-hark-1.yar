rule Win_Trojan_Hark_1
{
strings:
	$a0 = { 0200550001000000ffff270700009d020000040000006a08 }


condition:
	$a0
}