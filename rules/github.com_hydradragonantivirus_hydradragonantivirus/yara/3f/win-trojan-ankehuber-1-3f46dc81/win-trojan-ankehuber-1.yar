rule Win_Trojan_AnkeHuber_1
{
strings:
	$a0 = { 01018dbe1501b9c301ad8bd0311547e2fb }


condition:
	$a0
}