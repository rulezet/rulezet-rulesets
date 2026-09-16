rule Win_Trojan__0121_0006_001_1
{
strings:
	$a0 = { 2126c745150000b440ba4902b90500cd21268b4d0d268b550fb80157cd21b43ecd211f075e }


condition:
	$a0
}