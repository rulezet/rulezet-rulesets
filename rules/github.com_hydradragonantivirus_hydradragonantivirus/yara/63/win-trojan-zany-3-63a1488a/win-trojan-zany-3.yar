rule Win_Trojan_Zany_3
{
strings:
	$a0 = { b5008d960001cd218b8601012d03008986b301b800 }


condition:
	$a0
}