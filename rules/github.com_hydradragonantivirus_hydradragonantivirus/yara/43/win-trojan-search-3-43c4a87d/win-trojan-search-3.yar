rule Win_Trojan_Search_3
{
strings:
	$a0 = { cd217303eb66908bd8b43f8bd683c204b90400cd21 }


condition:
	$a0
}