rule Win_Trojan_SillyE_2
{
strings:
	$a0 = { b440cd217259b0008b4c198b54178b5c0eb442cd217248b97b048d54fd8b5c0eb440cd2172 }


condition:
	$a0
}