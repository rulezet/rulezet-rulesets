rule Win_Trojan_BugHunter_1
{
strings:
	$a0 = { 21b440b905008d96c801cd21b8024233c999cd21b4408d960501b9c800cd21b801573e8b8ee301 }


condition:
	$a0
}