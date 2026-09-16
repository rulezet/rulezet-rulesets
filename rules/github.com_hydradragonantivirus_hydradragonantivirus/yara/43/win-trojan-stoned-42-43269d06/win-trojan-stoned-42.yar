rule Win_Trojan_Stoned_42
{
strings:
	$a0 = { 0900c333c08ed8fa8ed0bc007cfba14c002ea30900a14e002ea30b00a113044848a31304b106 }


condition:
	$a0
}