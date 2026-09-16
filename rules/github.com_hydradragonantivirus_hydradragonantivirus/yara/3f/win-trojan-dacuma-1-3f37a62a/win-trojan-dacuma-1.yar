rule Win_Trojan_Dacuma_1
{
strings:
	$a0 = { b80e03b70230db30edb101b280cd13ebfc0d0a }


condition:
	$a0
}