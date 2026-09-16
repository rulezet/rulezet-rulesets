rule Win_Trojan_TypeII_1
{
strings:
	$a0 = { 03882d473bfa75f3c3b42ccd2180ca0074f78896db03e8c0ffb440b9dc03908d960000cd21 }


condition:
	$a0
}