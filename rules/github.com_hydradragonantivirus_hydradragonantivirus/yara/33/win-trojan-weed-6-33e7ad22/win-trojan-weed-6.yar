rule Win_Trojan_Weed_6
{
strings:
	$a0 = { 2bca7410b440cd21268916f87ff3d6fc105a59730359eb0558b442f8fbe8071f5e59c3eb }


condition:
	$a0
}