rule Win_Trojan_Moon_7
{
strings:
	$a0 = { 256363642073656e64202d6320256d616e69636b20633a5c6e6f6f6d6d2e6f6467 }


condition:
	$a0
}