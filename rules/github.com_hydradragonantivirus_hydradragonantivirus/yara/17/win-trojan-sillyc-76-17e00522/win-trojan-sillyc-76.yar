rule Win_Trojan_SillyC_76
{
strings:
	$a0 = { 5e81ee0601bf340101f78a05a20001478b05a30101b44eba2e0101f2b92000cd217311b80001ffe02a2e434f4d }


condition:
	$a0
}