rule Win_Trojan_Marvin_1
{
strings:
	$a0 = { bd0000929287ca87ca87cae81600eb26e811008d960301b95701b440cd21e80300c3 }


condition:
	$a0
}