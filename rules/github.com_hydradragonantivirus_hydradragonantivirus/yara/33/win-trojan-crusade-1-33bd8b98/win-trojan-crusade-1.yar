rule Win_Trojan_Crusade_1
{
strings:
	$a0 = { 83ef032e898552022e899d54022e898d56022e899558022e8c855a02b452cd21268b47fe0e072e8b9d5a024b8ed839 }


condition:
	$a0
}