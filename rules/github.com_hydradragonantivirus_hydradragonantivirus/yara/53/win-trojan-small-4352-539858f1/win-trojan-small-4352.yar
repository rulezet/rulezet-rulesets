rule Win_Trojan_Small_4352
{
strings:
	$a0 = { 89c689c789c381c0008abffff7d85050e82300000029c05050 }


condition:
	$a0
}