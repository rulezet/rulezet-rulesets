rule Win_Trojan_Fakeav_44
{
strings:
	$a0 = { 8bff558bec83ec2c575603d8897dfc8d058684410050ff155090410043e8defb }


condition:
	$a0
}