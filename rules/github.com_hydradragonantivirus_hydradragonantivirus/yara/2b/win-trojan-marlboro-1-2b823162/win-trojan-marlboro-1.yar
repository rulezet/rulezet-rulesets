rule Win_Trojan_Marlboro_1
{
strings:
	$a0 = { e947ff502d030089860a035ab80042cd21b440b91d008d960401cd218db62101b92701518b }


condition:
	$a0
}