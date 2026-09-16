rule Win_Trojan_Slimeline_1
{
strings:
	$a0 = { 3e898606013e8986ea01b440b1e68d960401cd2133c0e83500b440b1048d96e801cd21b801 }


condition:
	$a0
}