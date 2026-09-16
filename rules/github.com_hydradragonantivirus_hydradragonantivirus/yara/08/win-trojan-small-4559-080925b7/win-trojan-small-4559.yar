rule Win_Trojan_Small_4559
{
strings:
	$a0 = { 81c021a1400068435304006822749800 }


condition:
	$a0
}