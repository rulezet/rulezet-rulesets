rule Win_Trojan_Nohope_1
{
strings:
	$a0 = { 0300cd217268538bda803fe95b744cb8024233c933d2cd21725450b4408bd683ea0bb90201cd21 }


condition:
	$a0
}