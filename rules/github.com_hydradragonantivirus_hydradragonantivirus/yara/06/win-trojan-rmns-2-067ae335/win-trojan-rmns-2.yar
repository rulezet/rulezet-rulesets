rule Win_Trojan_RMNS_2
{
strings:
	$a0 = { 81ee0601bffe0101f78a05a20001478b05a30101b8bb4bcd213db4bb7503e9d1008cc8488ec026a000003c5a74050e }


condition:
	$a0
}