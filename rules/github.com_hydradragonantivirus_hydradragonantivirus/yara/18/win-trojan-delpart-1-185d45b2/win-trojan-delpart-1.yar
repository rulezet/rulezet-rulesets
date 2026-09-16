rule Win_Trojan_DelPart_1
{
strings:
	$a0 = { b90100ba80010e07bba401cd130e1f7205ba3901eb03ba7101b409cd21b8004ccd210a0d50 }


condition:
	$a0
}