rule Win_Trojan_ExeHeader_8
{
strings:
	$a0 = { 0200ba80002bc2be0001bb92018ec0fcbf0001b90002f3 }


condition:
	$a0
}