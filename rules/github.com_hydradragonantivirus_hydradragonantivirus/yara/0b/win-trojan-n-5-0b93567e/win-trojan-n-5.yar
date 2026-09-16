rule Win_Trojan_N_5
{
strings:
	$a0 = { e80000cd01e81600e800005d81ed0e01e8cc02e84302e80d00e84602eb2cb8050333dbcd16c3b9eb09b805feebfc80c4 }


condition:
	$a0
}