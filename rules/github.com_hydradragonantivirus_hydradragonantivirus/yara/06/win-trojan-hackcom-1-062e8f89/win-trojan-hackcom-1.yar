rule Win_Trojan_HackCOM_1
{
strings:
	$a0 = { 8681343c874646cce2f7 }


condition:
	$a0
}