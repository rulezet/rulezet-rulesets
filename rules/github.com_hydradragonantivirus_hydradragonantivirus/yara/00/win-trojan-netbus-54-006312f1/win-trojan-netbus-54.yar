rule Win_Trojan_Netbus_54
{
strings:
	$a0 = { 6879294500e801000000c3c33caca61fa30d3215d104bd2a4ed9e8a0c3ed739696487febf8140053daaf76 }


condition:
	$a0
}