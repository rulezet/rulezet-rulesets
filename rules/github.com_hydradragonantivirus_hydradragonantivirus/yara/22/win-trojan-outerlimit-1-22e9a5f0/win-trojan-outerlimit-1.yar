rule Win_Trojan_OuterLimit_1
{
strings:
	$a0 = { b408b280cd13882ea005880ea1058836a205bb3101b001b9010032f6e8aefffcbe3101bfef05b92300f3a6e31a7500e8a9ffbbef05b001b9010032f6e895ffe84cffb8004ccd21e844ffebf6 }


condition:
	$a0
}