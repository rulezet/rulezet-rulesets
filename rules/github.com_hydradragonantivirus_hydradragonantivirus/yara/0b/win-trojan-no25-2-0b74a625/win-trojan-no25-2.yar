rule Win_Trojan_No25_2
{
strings:
	$a0 = { 19ef07075986e92707ef50010cea7304ee9507b337bc9df8ca263b047404ee830734f88bdf4f89df }


condition:
	$a0
}