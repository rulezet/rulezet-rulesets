rule Win_Trojan_V2100_2
{
strings:
	$a0 = { 0e1ff694f5073deb00750d33ffb909 }


condition:
	$a0
}