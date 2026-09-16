rule Win_Trojan_Evgenich_1
{
strings:
	$a0 = { be0001bf00f0b9a10051f3a4e900efbee804bf00015957f3a4ba00f1b41acd21ba9bf0b44ecd217308ba8000b41a }


condition:
	$a0
}