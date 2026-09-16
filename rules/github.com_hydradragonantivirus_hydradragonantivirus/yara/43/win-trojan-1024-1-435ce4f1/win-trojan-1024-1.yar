rule Win_Trojan_1024_1
{
strings:
	$a0 = { 8cc0488ec026a103002d800026a30300 }


condition:
	$a0
}