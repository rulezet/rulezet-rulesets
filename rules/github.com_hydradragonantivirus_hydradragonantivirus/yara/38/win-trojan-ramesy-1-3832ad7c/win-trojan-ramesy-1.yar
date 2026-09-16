rule Win_Trojan_Ramesy_1
{
strings:
	$a0 = { 440157be0001b9a800a5e2fd5d8d961400ffe2bf000157 }


condition:
	$a0
}