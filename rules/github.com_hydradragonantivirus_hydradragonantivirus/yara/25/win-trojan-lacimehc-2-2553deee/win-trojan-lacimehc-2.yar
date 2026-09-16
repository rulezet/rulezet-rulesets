rule Win_Trojan_Lacimehc_2
{
strings:
	$a0 = { e800005d81ed06011f060e0e1f07b9a2028db6????8bfee80300[1-3]acd0c8d0c8d0c8d0c8f6d83e3286????f6d8d0c8d0c8d0c8d0c8aae2e3c3 }


condition:
	$a0
}