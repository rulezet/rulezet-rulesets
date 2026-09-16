rule Win_Trojan_Level3_3
{
strings:
	$a0 = { fd3030b8982db9a92b3104af1c04b206672806230ffc2fc1f8824205ebef }


condition:
	$a0
}