rule Win_Trojan_Finnish_2
{
strings:
	$a0 = { 30008ec2268b16000081fa8680740a }


condition:
	$a0
}