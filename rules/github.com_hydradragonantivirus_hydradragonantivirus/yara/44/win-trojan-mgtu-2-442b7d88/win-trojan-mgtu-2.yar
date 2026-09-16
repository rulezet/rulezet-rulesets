rule Win_Trojan_MGTU_2
{
strings:
	$a0 = { be00018b0589048b4502894402b8 }


condition:
	$a0
}