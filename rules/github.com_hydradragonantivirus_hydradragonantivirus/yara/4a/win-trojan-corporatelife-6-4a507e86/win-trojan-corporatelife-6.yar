rule Win_Trojan_CorporateLife_6
{
strings:
	$a0 = { 06904f0e474f4ffb1f4f9090fbbe1d074fbb3e014f4f803779474347474e75f6904f904747fb4ffbfbfbfb9090fb4f }


condition:
	$a0
}