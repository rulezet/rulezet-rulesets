rule Win_Trojan_Zero_6
{
strings:
	$a0 = { 83eb0426891e020026c7060000f5e9bfcfcfc53690 }


condition:
	$a0
}