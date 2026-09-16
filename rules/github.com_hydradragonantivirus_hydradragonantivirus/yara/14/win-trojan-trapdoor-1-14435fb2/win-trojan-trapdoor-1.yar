rule Win_Trojan_TrapDoor_1
{
strings:
	$a0 = { 9292929287ca87ca87ca87cae81600eb26e811008d960301b95201b440cd21e80300c3 }


condition:
	$a0
}