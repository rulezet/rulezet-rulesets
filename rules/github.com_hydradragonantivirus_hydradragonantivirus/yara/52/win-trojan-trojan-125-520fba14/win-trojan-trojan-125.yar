rule Win_Trojan_Trojan_125
{
strings:
	$a0 = { 1e008ec08cc88ed8fcbf0000b90502f3a4b800008ed88b }


condition:
	$a0
}