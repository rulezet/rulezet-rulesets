rule Win_Trojan_Monster_48
{
strings:
	$a0 = { 74fa0d8074fd0deb00b00db97e02f130044be2fb }


condition:
	$a0
}