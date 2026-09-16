rule Win_Trojan_Sunday_2
{
strings:
	$a0 = { 5e81ee170b8bfe57501e060e070e1fb604b9140bac }


condition:
	$a0
}