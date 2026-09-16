rule Win_Trojan_Pogue_3
{
strings:
	$a0 = { b8dadacd2180fca57468b80030cd21 }


condition:
	$a0
}