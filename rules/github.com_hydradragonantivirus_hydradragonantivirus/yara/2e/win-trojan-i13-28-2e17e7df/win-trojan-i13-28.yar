rule Win_Trojan_I13_28
{
strings:
	$a0 = { ed0301b83030cd213d13cd744eb82135cd212e899e0e022e8c8610028cd8488ec026a103002d210093b44a1e07cd }


condition:
	$a0
}