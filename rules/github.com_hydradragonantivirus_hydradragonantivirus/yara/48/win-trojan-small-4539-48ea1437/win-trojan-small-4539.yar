rule Win_Trojan_Small_4539
{
strings:
	$a0 = { b8f6??400096ad6a016a026a036a04ffd095 }


condition:
	$a0
}