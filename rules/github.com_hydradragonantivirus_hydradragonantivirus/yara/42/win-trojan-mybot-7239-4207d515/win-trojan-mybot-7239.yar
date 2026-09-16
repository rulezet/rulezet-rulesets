rule Win_Trojan_Mybot_7239
{
strings:
	$a0 = { bf391069a0b52e212614729c83ddf4908bb1387504bab3c1fee76758f82aadac38ca96cde1f64435f4c54f2ec1e687cda07515c4e9bbc91a0f4c8906b3bbd1b7d833392b3e2afd09b6f702e9aa9d }


condition:
	$a0
}