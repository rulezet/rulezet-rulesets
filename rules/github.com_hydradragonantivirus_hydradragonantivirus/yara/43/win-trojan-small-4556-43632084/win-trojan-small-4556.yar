rule Win_Trojan_Small_4556
{
strings:
	$a0 = { 81c0214d400068435304006822749800 }


condition:
	$a0
}