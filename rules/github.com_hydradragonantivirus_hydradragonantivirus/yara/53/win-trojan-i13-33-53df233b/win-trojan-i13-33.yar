rule Win_Trojan_I13_33
{
strings:
	$a0 = { ed0301b84d54cd213d4c42744eb82135cd212e899ecb012e8c86cd018cd8488ec026a103002d3a0093b44a1e07cd }


condition:
	$a0
}