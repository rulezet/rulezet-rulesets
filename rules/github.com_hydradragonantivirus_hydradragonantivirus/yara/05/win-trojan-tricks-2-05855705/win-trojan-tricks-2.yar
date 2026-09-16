rule Win_Trojan_Tricks_2
{
strings:
	$a0 = { 0301e88300551e03ab551e01ab1ee4273e09ab9963678bd8f012a8971034aa678b21721e95273e03ab13aeaa67 }


condition:
	$a0
}