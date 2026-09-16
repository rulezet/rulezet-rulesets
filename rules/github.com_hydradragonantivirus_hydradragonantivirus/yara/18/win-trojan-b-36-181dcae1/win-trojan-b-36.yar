rule Win_Trojan_B_36
{
strings:
	$a0 = { b313ff0f8b07b106d3e02dc00750bb4e008907bb4a008907bb4c00b8e57c8907bb4800b8867d }


condition:
	$a0
}