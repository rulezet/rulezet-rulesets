rule Win_Trojan__Girl_2
{
strings:
	$a0 = { 06f1000800befd05bf0001b99600acaae2fcbe9601b915 }


condition:
	$a0
}