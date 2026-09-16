rule Win_Trojan_Gen_62
{
strings:
	$a0 = { 2012bb0500cd2f534b4b26881db81612cd2f4b4b26891d }


condition:
	$a0
}