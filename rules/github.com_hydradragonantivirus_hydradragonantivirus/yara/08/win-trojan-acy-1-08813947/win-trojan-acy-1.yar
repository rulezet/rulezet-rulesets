rule Win_Trojan_Acy_1
{
strings:
	$a0 = { b96f0032c0f3aa8d9663fdb440b91603cd2172135a5983e1 }


condition:
	$a0
}