rule Win_Trojan_Shadow_6
{
strings:
	$a0 = { 540183c203b442cd2189f283c203b9 }


condition:
	$a0
}