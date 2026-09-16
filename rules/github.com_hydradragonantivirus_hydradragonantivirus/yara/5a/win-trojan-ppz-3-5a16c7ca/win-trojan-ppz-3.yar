rule Win_Trojan_PPZ_3
{
strings:
	$a0 = { 071f5f5e5a595b58cf061d001f001a36566972757320225a2d0a554465ec682066fe1400fb50 }


condition:
	$a0
}