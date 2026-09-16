rule Win_Trojan_MBuck_3
{
strings:
	$a0 = { 750a8a867efe3a06510174098dbe00ff1657e840fe89ec5dc20400052a2e636f6d5589e5 }


condition:
	$a0
}