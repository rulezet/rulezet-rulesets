rule Win_Trojan_SomeKit_2
{
strings:
	$a0 = { cd20005059ba01fab8455992cd1692929292b9a701bb28002e8107000083c30283e9 }


condition:
	$a0
}