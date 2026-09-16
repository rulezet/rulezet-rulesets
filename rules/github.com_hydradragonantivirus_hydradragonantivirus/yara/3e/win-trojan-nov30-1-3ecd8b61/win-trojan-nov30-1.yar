rule Win_Trojan_Nov30_1
{
strings:
	$a0 = { f0cd2180fcf0741380fcff750eb4f1 }


condition:
	$a0
}