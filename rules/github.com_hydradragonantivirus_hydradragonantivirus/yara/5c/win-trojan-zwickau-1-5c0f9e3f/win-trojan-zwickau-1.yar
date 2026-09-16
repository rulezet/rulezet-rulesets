rule Win_Trojan_Zwickau_1
{
strings:
	$a0 = { cd21b44033d2b9f901cd215a59b80157cd21b43ecd }


condition:
	$a0
}