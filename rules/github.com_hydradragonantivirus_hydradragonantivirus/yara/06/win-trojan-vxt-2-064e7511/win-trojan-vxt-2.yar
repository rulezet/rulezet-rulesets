rule Win_Trojan_VXT_2
{
strings:
	$a0 = { b56301572e8aa54d018bfeb9f201ac32c4aae2fa }


condition:
	$a0
}