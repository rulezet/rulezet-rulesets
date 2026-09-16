rule Win_Trojan_Cinder_1
{
strings:
	$a0 = { b4fbcd210ae4742933c05007be0001bf }


condition:
	$a0
}