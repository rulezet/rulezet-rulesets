rule Win_Trojan_HappyNewYear_3
{
strings:
	$a0 = { ed030150b452cd21268b57febf3a033e8913bf3a033e8e03268b160300423e011326803e00005a75e9068cc22603 }


condition:
	$a0
}