rule Win_Trojan_Spider_1
{
strings:
	$a0 = { 021e579a3e0955019a0e025501b8dc05509a9e02f300bf88021e57bfaf020e5731c0509a060a }


condition:
	$a0
}