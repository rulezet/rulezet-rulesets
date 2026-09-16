rule Win_Trojan_Tricks_7
{
strings:
	$a0 = { 816e0003018b760083c402e88300551e6eab551e6cab1ee4273e14ab9963678bd8f012a8971034aa678b21721e95 }


condition:
	$a0
}