rule Win_Trojan_Funeral_2
{
strings:
	$a0 = { dfdf3d584575d8e80a01b91800b43fbaa403e895017239813ea4034d5a7531 }


condition:
	$a0
}