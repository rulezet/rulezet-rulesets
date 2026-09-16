rule Win_Trojan_Dikshev_5
{
strings:
	$a0 = { 8bd581ea3c3281c2323233c9b1c0cd21b8fd41404040998bcacd218bc48bf840404096ad9681 }


condition:
	$a0
}