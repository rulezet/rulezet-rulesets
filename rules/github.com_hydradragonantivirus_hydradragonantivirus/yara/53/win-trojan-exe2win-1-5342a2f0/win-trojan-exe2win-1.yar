rule Win_Trojan_Exe2Win_1
{
strings:
	$a0 = { 9c00007517ba9e00b8013dcd2193b440ba0001b9b600cd21b43ecd21b44fcd2173dac3 }


condition:
	$a0
}