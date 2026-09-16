rule Win_Trojan_Night_1
{
strings:
	$a0 = { c88cdb3bc3740b1e06060e1ffae8fb01eb121e068cc80539012d03008ed8fae8e901eb49d79f3ff9397c3dfcf93925 }


condition:
	$a0
}