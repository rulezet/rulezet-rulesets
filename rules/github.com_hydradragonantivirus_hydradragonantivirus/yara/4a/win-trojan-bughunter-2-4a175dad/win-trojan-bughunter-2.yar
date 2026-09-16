rule Win_Trojan_BugHunter_2
{
strings:
	$a0 = { 40b905008d96ce01cd21b8024233c999cd21b4408d960501b9ce00cd21b801573e8b8ee901 }


condition:
	$a0
}