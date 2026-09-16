rule Win_Trojan_Tricks_1
{
strings:
	$a0 = { 0301ffb48a01ffb48c01b44e8d94840133c9cd217259b8023dba9e00cd218bd8b43f8d948a01b90400cd2180bc }


condition:
	$a0
}