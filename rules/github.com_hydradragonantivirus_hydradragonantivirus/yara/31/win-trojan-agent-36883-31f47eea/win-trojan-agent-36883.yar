rule Win_Trojan_Agent_36883
{
strings:
	$a0 = { 5058535b90bbdc????00ffe390cccccc558bec5dc3cccccccccccccccccccccc }


condition:
	$a0
}