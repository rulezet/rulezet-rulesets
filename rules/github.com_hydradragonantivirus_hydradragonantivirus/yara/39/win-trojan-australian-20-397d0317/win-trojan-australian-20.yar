rule Win_Trojan_Australian_20
{
strings:
	$a0 = { a099292e9424252132dc8d023d2f41 }


condition:
	$a0
}