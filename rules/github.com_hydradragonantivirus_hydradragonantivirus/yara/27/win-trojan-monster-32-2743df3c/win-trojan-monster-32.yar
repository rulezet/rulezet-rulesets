rule Win_Trojan_Monster_32
{
strings:
	$a0 = { 0d48e94a4bc0ce0348e8484bf26e6ff06b48499c876b1cfe0d7898cb8c1d48876b14a103b4ce0748 }


condition:
	$a0
}