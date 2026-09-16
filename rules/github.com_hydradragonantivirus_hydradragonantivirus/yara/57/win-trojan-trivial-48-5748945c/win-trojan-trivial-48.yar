rule Win_Trojan_Trivial_48
{
strings:
	$a0 = { ee03b44eb120ba470003d6cd21ba9e00b8013dcd21568bd6b91503bf150303febe0001e8000081c115035e8bd8ba }


condition:
	$a0
}