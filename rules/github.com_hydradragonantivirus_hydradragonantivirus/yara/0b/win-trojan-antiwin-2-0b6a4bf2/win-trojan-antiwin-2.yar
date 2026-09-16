rule Win_Trojan_Antiwin_2
{
strings:
	$a0 = { 8ed8803e72043c7448fabe0304ad484e4e8904fbb1 }


condition:
	$a0
}