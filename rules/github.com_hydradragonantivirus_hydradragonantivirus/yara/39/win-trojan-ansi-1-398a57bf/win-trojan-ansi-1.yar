rule Win_Trojan_ANSI_1
{
strings:
	$a0 = { 8661048d960203b440b96f01cd21b800422bd22bc9cd218d966004b440b90300cd21e840005a }


condition:
	$a0
}