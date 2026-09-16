rule Win_Trojan_DoNothing_1
{
strings:
	$a0 = { 8cca8edaba00988ec2f3a41eb800008e }


condition:
	$a0
}