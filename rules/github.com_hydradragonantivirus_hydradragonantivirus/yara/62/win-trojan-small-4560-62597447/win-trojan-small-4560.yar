rule Win_Trojan_Small_4560
{
strings:
	$a0 = { 81c0214f400068435304006822749800 }


condition:
	$a0
}