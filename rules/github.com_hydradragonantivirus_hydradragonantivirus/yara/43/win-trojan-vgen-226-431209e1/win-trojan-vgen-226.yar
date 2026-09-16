rule Win_Trojan_VGEN_226
{
strings:
	$a0 = { fa8cdd8cc88ed80500168ec0bf00005e83ee03b90016f3a4bbf0008ed8892f50b8000150cb2f038b2ef0008ec5 }


condition:
	$a0
}