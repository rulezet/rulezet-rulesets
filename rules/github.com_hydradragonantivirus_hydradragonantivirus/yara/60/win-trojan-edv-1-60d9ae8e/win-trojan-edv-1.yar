rule Win_Trojan_EDV_1
{
strings:
	$a0 = { 5083ec04b80001cfb601b9082751 }


condition:
	$a0
}