rule Win_Trojan_Satanik_1
{
strings:
	$a0 = { 03003e89860102b8004233c933d2cd21b440b903008d960002cd21b8024233c933d2cd21 }


condition:
	$a0
}