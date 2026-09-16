rule Win_Trojan_Rape_16
{
strings:
	$a0 = { cd6933d2b440b9f40190cd695a59b80157cd69 }


condition:
	$a0
}