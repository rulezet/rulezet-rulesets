rule Win_Trojan_V2100_1
{
strings:
	$a0 = { 1ff694f5073deb00750d33ffb9 }


condition:
	$a0
}