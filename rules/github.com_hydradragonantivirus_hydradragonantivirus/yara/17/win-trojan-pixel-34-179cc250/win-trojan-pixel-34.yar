rule Win_Trojan_Pixel_34
{
strings:
	$a0 = { 8cc80500108ec0be0001b973019033fff3a4ba3701b41acd21b44eba2b01b90600cd217270b8023dba5501cd218bd8 }


condition:
	$a0
}