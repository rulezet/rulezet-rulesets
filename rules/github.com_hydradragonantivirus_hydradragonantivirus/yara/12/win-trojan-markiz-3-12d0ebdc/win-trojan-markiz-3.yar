rule Win_Trojan_Markiz_3
{
strings:
	$a0 = { 5db916051e33c08ed881ed03018db63701fa51b1cb870c0e8d862301501e56cb2e8134 }


condition:
	$a0
}