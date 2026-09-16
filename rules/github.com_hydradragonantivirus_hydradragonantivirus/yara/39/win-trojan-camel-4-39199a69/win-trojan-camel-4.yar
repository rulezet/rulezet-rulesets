rule Win_Trojan_Camel_4
{
strings:
	$a0 = { 2c80f466bbffffcd2181eb1d00b8002c350066cd21b8002c350064bb1c00cd218ec0488ed8 }


condition:
	$a0
}