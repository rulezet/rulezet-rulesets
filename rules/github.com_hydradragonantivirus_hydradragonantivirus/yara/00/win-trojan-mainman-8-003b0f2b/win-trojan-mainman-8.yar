rule Win_Trojan_Mainman_8
{
strings:
	$a0 = { b9380001ca81ed0601b90300bf50018db6d00283ef5057f3a4b71a8d961a038ae7cd21e89300b74e8ae78d96 }


condition:
	$a0
}