rule Win_Trojan_Extasy_1
{
strings:
	$a0 = { b440ba4002cd21b8004233c999cd218bd7b44059cd215a59b80157cd21b43ecd21eb2a }


condition:
	$a0
}