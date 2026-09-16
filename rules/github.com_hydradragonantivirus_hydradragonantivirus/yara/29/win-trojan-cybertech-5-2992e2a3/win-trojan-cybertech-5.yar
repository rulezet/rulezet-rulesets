rule Win_Trojan_CyberTech_5
{
strings:
	$a0 = { d700b4408d5604b9df00cd21b80042e8dbffb4408d96d600b90400cd21e80e00b41aba8000 }


condition:
	$a0
}