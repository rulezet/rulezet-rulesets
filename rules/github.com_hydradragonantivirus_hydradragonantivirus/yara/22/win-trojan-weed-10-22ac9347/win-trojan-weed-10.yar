rule Win_Trojan_Weed_10
{
strings:
	$a0 = { 2bca7410b440cd21268916f0fff3d6fc105a59730359eb0558b4f0f742e8071f5e59c3eb }


condition:
	$a0
}