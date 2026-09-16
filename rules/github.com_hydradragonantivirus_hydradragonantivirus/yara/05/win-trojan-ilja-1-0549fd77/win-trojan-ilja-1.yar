rule Win_Trojan_Ilja_1
{
strings:
	$a0 = { 01b9100680371183c30173078cd80500108ed8e2ef }


condition:
	$a0
}