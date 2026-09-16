rule Win_Trojan_NightFall_3
{
strings:
	$a0 = { e9f57db30116d971b6701ac9f973162c5c62088c0a6a61c5efd701a09bac14cf3add299804588fc23ca358ab7f9b530e5510c7a0ed0748c9f209 }


condition:
	$a0
}